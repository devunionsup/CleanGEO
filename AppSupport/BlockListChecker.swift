//
//  BlockListChecker.swift
//  CleanGEO
//
//  In-memory matcher for blocked domains, loaded from the compiled filter set.
//

import Foundation

public final class BlockListChecker {

    private var blockedSuffixes: Set<String> = []
    private var allowed: Set<String> = []
    private let lock = NSLock()
    public private(set) var ruleCount = 0

    public init() {}

    /// Load from the app-group compiled rules file (domain-style rules only).
    public func loadFromAppGroup() {
        guard let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: FilterListManager.appGroupID) else { return }
        let url = container.appendingPathComponent("Filters", isDirectory: true)
            .appendingPathComponent(FilterListManager.blockerRulesFileName)
        guard let data = try? Data(contentsOf: url),
              let rules = try? JSONDecoder().decode([CompiledRule].self, from: data) else { return }
        var block: Set<String> = []
        var allow: Set<String> = []
        for r in rules {
            guard let f = r.trigger.urlFilter else { continue }
            let isException = r.action.type == "ignore-previous-rules"
            // Extract the host-ish core of the pattern.
            let s = f
                .replacingOccurrences(of: "^[a-z-]+://([a-z0-9-]+\\.)*", with: "", options: .regularExpression)
                .replacingOccurrences(of: "([/:?#]|$)", with: "", options: .regularExpression)
                .replacingOccurrences(of: "^", with: "")
                .replacingOccurrences(of: "$", with: "")
            guard s.contains(".") else { continue }
            if isException {
                allow.insert(s)
            } else {
                block.insert(s)
            }
        }
        lock.lock()
        blockedSuffixes = block
        allowed = allow
        ruleCount = block.count
        lock.unlock()
    }

    public func isBlocked(_ host: String) -> Bool {
        let h = host.lowercased().hasSuffix(".") ? String(host.dropLast()) : host.lowercased()
        // Whitelist wins.
        for a in allowed where h == a || h.hasSuffix("." + a) { return false }
        for b in blockedSuffixes where h == b || h.hasSuffix("." + b) { return true }
        return false
    }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        blockedSuffixes.removeAll()
        allowed.removeAll()
        ruleCount = 0
    }
}

//
//  ISPBlockDetector.swift
//  CleanGEO
//
//  Detects ISP-level DNS hijacking / NXDOMAIN interception and IP-level
//  blocking, and decides whether the CleanGEO tunnel is required.
//

import Foundation
import Network

public final class ISPBlockDetector: ObservableObject {

    public static let shared = ISPBlockDetector()

    /// Well-known canary domains that must NOT resolve if DNS is clean.
    private let canaryDomains = [
        "webexcellence.su",      // historic sinkhole canary
        "example-isblocked.test"
    ]

    /// Control domains that must always resolve.
    private let controlDomains = ["example.com", "www.wikipedia.org", "www.ge"]

    @Published public private(set) var dnsHijackDetected = false
    @Published public private(set) var ipBlockDetected = false
    @Published public private(set) var lastCheck: Date?
    @Published public private(set) var tunnelRequired = false

    private let resolver = RecursiveResolver()

    public init() {}

    /// Detect DNS hijack: resolve a canary via the system resolver. If it
    /// returns an address that the CleanGEO recursive path disagrees with,
    /// the ISP is intercepting DNS.
    public func check() async {
        var hijack = false
        for d in canaryDomains {
            // System resolver via CFNetwork-level getaddrinfo.
            let sysIPs = Self.systemResolve(d)
            let ours = (try? resolver.resolve(d))?.addresses ?? []
            if !sysIPs.isEmpty && !ours.isEmpty && Set(sysIPs) != Set(ours) {
                hijack = true
                break
            }
        }
        dnsHijackDetected = hijack

        // IP-block detection: TCP connect to well-known hosts on 443.
        var ipBlock = false
        for host in controlDomains {
            let sysIPs = Self.systemResolve(host)
            guard let ip = sysIPs.first else { continue }
            let reachable = await Self.tcpReachable(ip, port: 443, timeout: 3)
            if !reachable { ipBlock = true; break }
        }
        ipBlockDetected = ipBlock
        tunnelRequired = hijack || ipBlock
        lastCheck = Date()
    }

    static func systemResolve(_ host: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var info: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, nil, &hints, &info)
        guard rc == 0, let first = info else { return [] }
        defer { freeaddrinfo(info) }
        var out: [String] = []
        var cur: UnsafeMutablePointer<addrinfo>? = first
        while let c = cur {
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(c.pointee.ai_addr, socklen_t(c.pointee.ai_addrlen),
                           &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                out.append(String(cString: buf))
            }
            cur = c.pointee.ai_next
        }
        return out
    }

    static func tcpReachable(_ ip: String, port: UInt16, timeout: TimeInterval) async -> Bool {
        await withCheckedThrowingContinuation { cont in
            let conn = NWConnection(host: NWEndpoint.Host(ip),
                                    port: NWEndpoint.Port(rawValue: port)!,
                                    using: .tcp)
            let done = { (ok: Bool) in
                conn.cancel()
                cont.resume(returning: ok)
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: done(true)
                case .failed, .cancelled: done(false)
                default: break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { done(false) }
        }
    }
}
