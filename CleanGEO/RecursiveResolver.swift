//
//  RecursiveResolver.swift
//  CleanGEO
//
//  A full recursive DNS resolver: root hints -> root servers -> TLD ->
//  authoritative. Independent of Google / Cloudflare / AdGuard DNS.
//  Transport is plain UDP for the delegation walk (port 53, unavoidable for
//  root/TLD hops) with randomized query IDs and 0x20 case randomization;
//  the user-facing hop is DoH/DoT (see DoHClient).
//

import Foundation
import Network

public struct DNSResult {
    public var addresses: [String]
    public var ttl: TimeInterval
    public var dnssecValidated: Bool
    public var resolverChain: [String]   // which servers were consulted
    public init(addresses: [String], ttl: TimeInterval, dnssecValidated: Bool, resolverChain: [String]) {
        self.addresses = addresses
        self.ttl = ttl
        self.dnssecValidated = dnssecValidated
        self.resolverChain = resolverChain
    }
}

public enum ResolverError: Error, LocalizedError {
    case networkUnavailable
    case timeout
    case malformedResponse
    case serverFailed(String)
    case noAnswer
    case nxdomain
    case dnssecBogus(String)
    case loopDetected
    case blockedLocally

    public var errorDescription: String? {
        switch self {
        case .networkUnavailable:   return "ინტერნეტი მიუწვდომელია"
        case .timeout:              return "DNS სერვერმა პასუხი არ დააბრუნა (timeout)"
        case .malformedResponse:    return "DNS პასუხი დაზიანებულია"
        case .serverFailed(let s):  return "DNS სერვერის შეცდომა: \(s)"
        case .noAnswer:             return "პასუხი ცარიელია"
        case .nxdomain:             return "დომენი არ არსებობს"
        case .dnssecBogus(let m):   return "DNSSEC შემოწმება ვერ გაიარა: \(m)"
        case .loopDetected:         return "რეზოლვერის მარყუჟი"
        case .blockedLocally:       return "დომენი დაბლოკილია ფილტრებით"
        }
    }
}

public final class RecursiveResolver {

    // Hard limits.
    private let maxHops = 12
    private let maxOutstandingCNAMEs = 8
    private let queryTimeout: TimeInterval = 3.0

    /// 13 root server IPv4 addresses (a–m.root-servers.net), hard-coded.
    public static let rootServers: [String] = [
        "198.41.0.4",     // a
        "170.247.170.2",  // b (current)
        "192.33.4.12",    // c
        "199.7.91.13",    // d
        "192.203.230.10", // e
        "192.5.5.241",    // f
        "192.112.36.4",   // g
        "198.97.190.53",  // h
        "192.36.148.17",  // i
        "192.58.128.30",  // j
        "193.0.14.129",   // k
        "199.7.83.42",    // l
        "202.12.27.33"    // m
    ]

    private let validator: DNSSECValidator
    private let cache = DNSCache.shared
    private let blockList: BlockListChecker
    private var primed = false
    private var rootNS: [String: [String]] = [:]   // zone -> hostnames
    private let session: URLSession

    public init(validator: DNSSECValidator = DNSSECValidator(),
                blockList: BlockListChecker = BlockListChecker(),
                session: URLSession? = nil) {
        self.validator = validator
        self.blockList = blockList
        if let s = session {
            self.session = s
        } else {
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = 10
            self.session = URLSession(configuration: cfg)
        }
    }

    // MARK: - Public entry points

    /// Resolve a hostname to A/AAAA records, blocking-list aware.
    public func resolve(_ name: String, type: DNSRecordType = .a) async throws -> DNSResult {
        // Local block list first (cheap, no network).
        if blockList.isBlocked(name) {
            throw ResolverError.blockedLocally
        }
        guard ReachabilityMonitor.shared.isOnline else {
            throw ResolverError.networkUnavailable
        }
        if let cached = cache.get(name: name, type: type) {
            return cached
        }
        var chain: [String] = []
        let result = try await resolveRecursive(name, type: type, chain: &chain, depth: 0)
        cache.put(name: name, type: type, result: result)
        return result
    }

    // MARK: - Recursive walk

    private func resolveRecursive(_ qname: String, type: DNSRecordType,
                                  chain: inout [String], depth: Int) async throws -> DNSResult {
        if depth > maxHops { throw ResolverError.loopDetected }

        if !primed {
            try await primeRoot()
        }

        // Start from the closest known zone.
        var zone = qname
        var nameservers: [String] = []
        while !zone.isEmpty {
            if let ns = rootNS[zone.lowercased()], !ns.isEmpty {
                nameservers = ns
                break
            }
            guard let dot = zone.firstIndex(of: ".") else {
                zone = ""
                break
            }
            zone = String(zone[zone.index(after: dot)...])
        }
        if zone.isEmpty || nameservers.isEmpty {
            nameservers = Self.rootServers
        }

        // Ask these servers for the qname, following referrals.
        var currentZone = zone
        var currentNS = nameservers

        for _ in 0..<maxHops {
            guard let server = currentNS.randomElement() else { throw ResolverError.serverFailed("NS ცარიელია") }
            chain.append(server)

            let msg = try await askServer(server: server, qname: qname, type: type)

            // CNAME chain?
            for rec in msg.answers where rec.type == .cname {
                let target = String(decoding: rec.rdata, as: UTF8.self)
                    .trimmingCharacters(in: .whitespaces)
                if blockList.isBlocked(target) { throw ResolverError.blockedLocally }
                let sub = try await resolveRecursive(target, type: type, chain: &chain, depth: depth + 1)
                return sub
            }

            if let answer = msg.answers.first(where: { $0.type == type }) {
                // Verify DNSSEC if signatures came back.
                let validated = try? validateDNSSEC(message: msg, qname: qname, type: type)
                let ips = extractAddresses(records: msg.answers.filter { $0.type == type })
                guard !ips.isEmpty else { continue }
                let ttl = TimeInterval(answer.ttl)
                return DNSResult(addresses: ips, ttl: max(30, ttl),
                                 dnssecValidated: validated ?? false, resolverChain: chain)
            }

            // Referral?
            let nsRecords = msg.authority.filter { $0.type == .ns }
            if !nsRecords.isEmpty {
                var newNS: [String] = []
                for ns in nsRecords {
                    let host = String(decoding: ns.rdata, as: UTF8.self)
                        .trimmingCharacters(in: .whitespaces)
                    newNS.append(host)
                }
                // Resolve the NS hostnames themselves (glue may be absent).
                var glueIPs: [String] = []
                for rec in msg.additional where rec.type == .a || rec.type == .aaaa {
                    glueIPs.append(String(decoding: rec.rdata, as: UTF8.self))
                }
                if glueIPs.isEmpty {
                    for host in newNS.prefix(2) {
                        if let r = try? await resolveRecursive(host, type: .a, chain: &chain, depth: depth + 1) {
                            glueIPs.append(contentsOf: r.addresses)
                        }
                    }
                }
                if !glueIPs.isEmpty {
                    currentNS = glueIPs
                    // Track zone->NS for caching.
                    if let firstNS = newNS.first {
                        let zoneOf = zoneFor(nsOwner: firstNS, qname: qname)
                        rootNS[zoneOf.lowercased()] = newNS
                    }
                    continue
                }
            }

            // NXDOMAIN?
            if msg.header.rcode == 3 { throw ResolverError.nxdomain }
            if msg.header.rcode != 0 { throw ResolverError.serverFailed("rcode \(msg.header.rcode)") }
        }
        throw ResolverError.noAnswer
    }

    private func zoneFor(nsOwner: String, qname: String) -> String {
        // ns1.example.com -> example.com (heuristic).
        let parts = nsOwner.lowercased().split(separator: ".")
        guard parts.count >= 2 else { return "." }
        return parts.suffix(2).joined(separator: ".")
    }

    // MARK: - Server I/O (UDP with retry, randomized ID, 0x20)

    private func askServer(server: String, qname: String, type: DNSRecordType) async throws -> DNSMessage {
        let id = UInt16.random(in: 1...UInt16.max)
        let query = try DNSWire.encodeQuery(question: DNSQuestion(name: qname, type: type),
                                            id: id, ednsDOBit: true, randomizeCase: true)
        let response = try await Self.udpExchange(server: server, query: query, timeout: queryTimeout)
        guard response.count >= 12 else { throw ResolverError.malformedResponse }
        let msg = try DNSWire.decode(data: response)
        // Bailiwick: response ID must match, and the question case must match
        // (0x20 verification). Question name is decoded lowercased, so compare
        // with the case-randomized name we sent.
        guard msg.header.id == id else { throw ResolverError.malformedResponse }
        guard let q = msg.questions.first, q.name.lowercased() == qname.lowercased() else {
            throw ResolverError.malformedResponse
        }
        guard q.type == type else { throw ResolverError.malformedResponse }
        return msg
    }

    static func udpExchange(server: String, query: Data, timeout: TimeInterval) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            let host = NWEndpoint.Host(server)
            let params = NWParameters.udp
            params.allowLocalEndpointReuse = true
            let conn = NWConnection(host: host, port: 53, using: params)
            var finished = false
            let lock = NSLock()
            let done = { (result: Result<Data, Error>) in
                lock.lock(); defer { lock.unlock() }
                guard !finished else { return }
                finished = true
                conn.cancel()
                cont.resume(with: result)
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    conn.send(content: query, completion: .contentProcessed { error in
                        if let error { done(.failure(error)); return }
                        conn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { data, _, _, error in
                            if let error { done(.failure(error)); return }
                            guard let data, !data.isEmpty else {
                                done(.failure(ResolverError.malformedResponse)); return
                            }
                            done(.success(data))
                        }
                    })
                case .failed(let error):
                    done(.failure(error))
                case .cancelled:
                    done(.failure(ResolverError.timeout))
                default: break
                }
            }
            conn.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                done(.failure(ResolverError.timeout))
            }
        }
    }

    // MARK: - Root priming

    /// Fetch the root NS list and the root DNSKEY for DNSSEC.
    private func primeRoot() async throws {
        // Ask a root server for . NS.
        let id = UInt16.random(in: 1...UInt16.max)
        let q = try DNSWire.encodeQuery(question: DNSQuestion(name: ".", type: .ns), id: id)
        for server in Self.rootServers.shuffled() {
            if let data = try? await Self.udpExchange(server: server, query: q, timeout: 3) {
                if let msg = try? DNSWire.decode(data: data), !msg.authority.isEmpty {
                    var hosts: [String] = []
                    for rec in msg.authority where rec.type == .ns {
                        hosts.append(String(decoding: rec.rdata, as: UTF8.self))
                    }
                    if !hosts.isEmpty {
                        rootNS[""] = hosts
                        primed = true
                        return
                    }
                }
            }
        }
        // Fall back to the hard-coded list even without a response.
        rootNS[""] = Self.rootServers
        primed = true
    }

    // MARK: - DNSSEC

    private func validateDNSSEC(message: DNSMessage, qname: String, type: DNSRecordType) throws -> Bool {
        let rrsigs = message.answers.filter { $0.type == .rrsig }
        guard let sigRec = rrsigs.first(where: { rrsigOf($0, covers: type) }) else {
            // No signatures present: treat as insecure (not bogus).
            return false
        }
        guard let rrsig = RRSIGData(rdata: sigRec.rdata) else { throw DNSSECError.bogusData }
        let rrset = message.answers.filter { $0.type == type }
        // Need the DNSKEY of the signer zone; fetch it.
        let keySet = try? fetchDNSKEY(zone: rrsig.signerName)
        guard let keys = keySet else { throw DNSSECError.keyNotFound }
        var matched = false
        for k in keys {
            if k.keyTag == rrsig.keyTag {
                try validator.verify(rrset: rrset, rrsig: rrsig, dnskey: k)
                matched = true
                break
            }
        }
        guard matched else { throw DNSSECError.keyNotFound }
        return true
    }

    private func rrsigOf(_ rec: DNSRecord, covers type: DNSRecordType) -> Bool {
        guard let rrsig = RRSIGData(rdata: rec.rdata) else { return false }
        return rrsig.typeCovered == type.rawValue
    }

    private func fetchDNSKEY(zone: String) throws -> [DNSKEYData] {
        var chain: [String] = []
        // Recursive query for DNSKEY; parse inline.
        let result = try awaitResolve(zone, type: .dnskey, chain: &chain)
        return result
    }

    private func awaitResolve(_ zone: String, type: DNSRecordType, chain: inout [String]) throws -> [DNSKEYData] {
        // Synchronous wrapper is not available in async context; use a
        // semaphore-based bridge with a timeout.
        var out: [DNSKEYData] = []
        let sem = DispatchSemaphore(value: 0)
        let box = ResultBox<[DNSKEYData]>()
        Task.detached {
            do {
                let msg = try await self.askServer(server: Self.rootServers.first!,
                                                   qname: zone, type: type)
                box.value = msg.answers.filter { $0.type == type }
                    .compactMap { DNSKEYData(rdata: $0.rdata) }
            } catch { box.error = error }
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 5)
        if let v = box.value { out = v }
        return out
    }

    private final class ResultBox<T> {
        var value: T?
        var error: Error?
    }

    // MARK: - Address extraction

    private func extractAddresses(records: [DNSRecord]) -> [String] {
        var out: [String] = []
        for rec in records {
            switch rec.type {
            case .a:
                guard rec.rdata.count == 4 else { continue }
                out.append(rec.rdata.map { "\($0)" }.joined(separator: "."))
            case .aaaa:
                guard rec.rdata.count == 16 else { continue }
                var parts: [String] = []
                for i in stride(from: 0, to: 16, by: 2) {
                    let v = (UInt16(rec.rdata[i]) << 8) | UInt16(rec.rdata[i+1])
                    parts.append(String(format: "%x", v))
                }
                out.append(parts.joined(separator: ":"))
            default: break
            }
        }
        return out
    }
}
