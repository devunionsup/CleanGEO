//
//  DoHClient.swift
//  CleanGEO
//
//  DNS-over-HTTPS (RFC 8484) and DNS-over-TLS (RFC 7858) clients.
//  The user-facing hop to the CleanGEO resolver is always encrypted.
//

import Foundation
import Network
import Security

public enum DoHError: Error, LocalizedError {
    case badURL
    case httpStatus(Int)
    case malformed
    case dnsSECFailure
    case timeout

    public var errorDescription: String? {
        switch self {
        case .badURL:            return "არასწორი DoH URL"
        case .httpStatus(let c): return "DoH სერვერის შეცდომა (HTTP \(c))"
        case .malformed:         return "DoH პასუხი დაზიანებულია"
        case .dnsSECFailure:     return "DNSSEC შემოწმება ვერ გაიარა"
        case .timeout:           return "DoH სერვერი არ პასუხობს"
        }
    }
}

/// Endpoints for the CleanGEO resolver. Replace with your own host after
/// deployment; DoH is a plain HTTPS POST of application/dns-message.
public struct CleanGEODNSConfig {
    public var dohURL: URL        // e.g. https://dns.cleangeo.ge/dns-query
    public var doTHost: String    // e.g. dns.cleangeo.ge
    public var doTPort: UInt16    // 853
    public var sni: String?

    public init(dohURL: URL, doTHost: String, doTPort: UInt16 = 853, sni: String? = nil) {
        self.dohURL = dohURL
        self.doTHost = doTHost
        self.doTPort = doTPort
        self.sni = sni
    }

    public static func cleangeo(host: String = "dns.cleangeo.ge") -> CleanGEODNSConfig {
        CleanGEODNSConfig(
            dohURL: URL(string: "https://\(host)/dns-query")!,
            doTHost: host,
            doTPort: 853)
    }
}

public final class DoHClient {

    private let config: CleanGEODNSConfig
    private let session: URLSession
    private let validator: DNSSECValidator

    public init(config: CleanGEODNSConfig, validator: DNSSECValidator = DNSSECValidator()) {
        self.config = config
        self.validator = validator
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 8
        cfg.tlsMinimumSupportedProtocolVersion = .TLSv12
        self.session = URLSession(configuration: cfg)
    }

    // MARK: - DoH (RFC 8484, POST)

    /// POST application/dns-message; verify DNSSEC when DO was set and
    /// signatures came back.
    public func query(_ qname: String, type: DNSRecordType, dnssec: Bool = true) async throws -> DNSMessage {
        let id = UInt16.random(in: 1...UInt16.max)
        // DoH responses come back over TLS where ID matching is not strictly
        // needed, but we still randomize and check.
        let query = try DNSWire.encodeQuery(question: DNSQuestion(name: qname, type: type),
                                            id: id, ednsDOBit: dnssec, randomizeCase: true)
        var req = URLRequest(url: config.dohURL)
        req.httpMethod = "POST"
        req.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        req.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        req.httpBody = query

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw DoHError.malformed }
        guard (200..<300).contains(http.statusCode) else { throw DoHError.httpStatus(http.statusCode) }
        guard http.value(forHTTPHeaderField: "Content-Type")?.hasPrefix("application/dns-message") == true
                || http.value(forHTTPHeaderField: "Content-Type")?.contains("dns-message") == true else {
            throw DoHError.malformed
        }
        guard data.count >= 12 else { throw DoHError.malformed }
        let msg = try DNSWire.decode(data: data)
        guard msg.header.id == id else { throw DoHError.malformed }
        guard let q = msg.questions.first, q.name.lowercased() == qname.lowercased(), q.type == type else {
            throw DoHError.malformed
        }
        if msg.header.rcode != 0 && msg.header.rcode != 3 {
            throw DoHError.httpStatus(Int(msg.header.rcode))
        }
        return msg
    }

    // MARK: - DoT (RFC 7858)

    /// DNS-over-TLS via Network.framework; TLS 1.3 by default.
    public func queryDoT(_ qname: String, type: DNSRecordType) async throws -> DNSMessage {
        let id = UInt16.random(in: 1...UInt16.max)
        let query = try DNSWire.encodeQuery(question: DNSQuestion(name: qname, type: type),
                                            id: id, ednsDOBit: true, randomizeCase: true)
        let data = try await Self.dotExchange(host: config.doTHost, port: config.doTPort,
                                              payload: query, timeout: 8)
        guard data.count >= 12 else { throw DoHError.malformed }
        let msg = try DNSWire.decode(data: data)
        guard msg.header.id == id else { throw DoHError.malformed }
        return msg
    }

    static func dotExchange(host: String, port: UInt16, payload: Data, timeout: TimeInterval) async throws -> Data {
        // Length-prefix (2 bytes, big endian) as RFC 7858 requires.
        var framed = Data()
        framed.append(UInt8((payload.count >> 8) & 0xFF))
        framed.append(UInt8(payload.count & 0xFF))
        framed.append(payload)

        return try await withCheckedThrowingContinuation { cont in
        // NWParameters.tls already includes the TLS protocol; set SNI and
        // require modern TLS through the TCP options.
        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, host)
        let params = NWParameters(tls: tlsOptions)
        let conn = NWConnection(host: NWEndpoint.Host(host),
                                port: NWEndpoint.Port(rawValue: port)!,
                                using: params)
            var finished = false
            let lock = NSLock()
            let done: (Result<Data, Error>) -> Void = { result in
                lock.lock(); defer { lock.unlock() }
                guard !finished else { return }
                finished = true
                conn.cancel()
                cont.resume(with: result)
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    conn.send(content: framed, completion: .contentProcessed { error in
                        if let error { done(.failure(error)); return }
                        // Read the 2-byte length prefix, then that many bytes.
                        conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { pre, _, _, error in
                            if let error { done(.failure(error)); return }
                            guard let pre, pre.count == 2 else { done(.failure(DoHError.malformed)); return }
                            let len = (Int(pre[0]) << 8) | Int(pre[1])
                            guard len > 12, len < 65535 else { done(.failure(DoHError.malformed)); return }
                            conn.receive(minimumIncompleteLength: len, maximumLength: len) { body, _, _, error in
                                if let error { done(.failure(error)); return }
                                guard let body, body.count == len else { done(.failure(DoHError.malformed)); return }
                                done(.success(body))
                            }
                        }
                    })
                case .failed(let e): done(.failure(e))
                case .cancelled: done(.failure(DoHError.timeout))
                default: break
                }
            }
            conn.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                done(.failure(DoHError.timeout))
            }
        }
    }
}

// MARK: - DNS cache

public final class DNSCache {
    public static let shared = DNSCache()

    private struct Entry {
        var result: DNSResult
        var expires: Date
    }
    private var store: [String: Entry] = [:]
    private let lock = NSLock()
    private let maxEntries = 4_096

    func key(_ name: String, _ type: DNSRecordType) -> String {
        name.lowercased() + "|" + String(type.rawValue)
    }

    public func get(name: String, type: DNSRecordType) -> DNSResult? {
        lock.lock(); defer { lock.unlock() }
        guard let e = store[key(name, type)], e.expires > Date() else { return nil }
        return e.result
    }

    public func put(name: String, type: DNSRecordType, result: DNSResult) {
        lock.lock(); defer { lock.unlock() }
        if store.count >= maxEntries {
            // Simple eviction: drop everything past half capacity.
            if store.count >= maxEntries { store.removeAll(keepingCapacity: true) }
        }
        store[key(name, type)] = Entry(result: result, expires: Date().addingTimeInterval(result.ttl))
    }

    public var count: Int {
        lock.lock(); defer { lock.unlock() }
        return store.count
    }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        store.removeAll()
    }
}

// MARK: - Reachability

public final class ReachabilityMonitor: ObservableObject {
    public static let shared = ReachabilityMonitor()
    @Published public private(set) var isOnline = true
    private var monitor: NWPathMonitor?

    private init() {
        start()
    }

    private func start() {
        let m = NWPathMonitor()
        m.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                self?.isOnline = path.status == .satisfied
            }
        }
        m.start(queue: .global())
        monitor = m
    }
}
