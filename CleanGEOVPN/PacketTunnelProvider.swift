//
//  PacketTunnelProvider.swift
//  CleanGEOVPN
//
//  LOCAL privacy tunnel. Nothing leaves the device except encrypted
//  DNS-over-HTTPS to the configured endpoints:
//
//    1. https://dns.adguard-dns.com/dns-query       (primary)
//    2. https://family.adguard-dns.com/dns-query    (automatic fallback)
//
//  The provider captures every DNS packet the system sends into the tunnel,
//  checks the App Group blocklist (the same compiled list Safari uses) and
//  answers 0.0.0.0 for blocked domains. Everything else is forwarded to the
//  primary DoH endpoint; if it fails (timeout / HTTP error / malformed
//  answer), the next endpoint in the chain is tried automatically and
//  remembered as the working one. Non-DNS traffic is refused locally by the
//  tunnel's routing, so no remote VPN server is ever contacted.
//

import NetworkExtension
import Foundation

final class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - State

    /// ბლოკლისტის მინიმალისტური წარმოდგენა — VPN target სხვა კლასებზე
    /// დამოკიდებულებს არ შეიცავს (ის აპის target-შია).
    private struct TunneledRule: Decodable {
        struct Trigger: Decodable { var urlFilter: String? }
        struct Action: Decodable { var type: String? }
        var trigger: Trigger?
        var action: Action?
    }

    private final class LocalBlocklist {
        private var blocked: Set<String> = []
        private var allowed: Set<String> = []
        private let lock = NSLock()

        func load() {
            guard let container = FileManager.default
                .containerURL(forSecurityApplicationGroupIdentifier: "group.87486bbbb00f533a.3") else { return }
            let url = container.appendingPathComponent("Filters", isDirectory: true)
                .appendingPathComponent("cleangeo-blocker.json")
            guard let data = try? Data(contentsOf: url),
                  let rules = try? JSONDecoder().decode([TunneledRule].self, from: data) else { return }
            var b: Set<String> = []
            var a: Set<String> = []
            for r in rules {
                guard let f = r.trigger?.urlFilter else { continue }
                let isException = r.action?.type == "ignore-previous-rules"
                let s = f
                    .replacingOccurrences(of: "^[a-z-]+://([a-z0-9-]+\\.)*", with: "", options: .regularExpression)
                    .replacingOccurrences(of: "([/:?#]|$)", with: "", options: .regularExpression)
                    .replacingOccurrences(of: "^", with: "")
                    .replacingOccurrences(of: "$", with: "")
                guard s.contains("."), s.count >= 4 else { continue }
                if isException { a.insert(s.lowercased()) } else { b.insert(s.lowercased()) }
            }
            lock.lock()
            blocked = b
            allowed = a
            lock.unlock()
        }

        func isBlocked(_ host: String) -> Bool {
            let h = host.lowercased()
            lock.lock(); defer { lock.unlock() }
            for x in allowed where h == x || h.hasSuffix("." + x) { return false }
            for x in blocked where h == x || h.hasSuffix("." + x) { return true }
            return false
        }
    }

    private var blocklist: LocalBlocklist?
    private var dohEndpoints: [(host: String, url: URL)] = []
    private var activeEndpointIndex = 0
    private var dnsSession: URLSession?
    private var flowReadActive = false

    // MARK: - Tunnel lifecycle

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        // 1) Blocklist from the App Group (same compiled list Safari uses).
        let checker = LocalBlocklist()
        checker.load()
        blocklist = checker

        // 2) providerConfiguration written by the app.
        let cfg = protocolConfiguration as? NETunnelProviderProtocol
        let pc = cfg?.providerConfiguration as? [String: Any] ?? [:]

        // DoH chain: primary first, fallback second. The app ships the
        // AdGuard chain by default; the user's custom DoH (cg.doh) is
        // prepended by the app when set.
        var chain: [String] = []
        if let provided = pc["dohChain"] as? String {
            chain = provided.split(separator: " ").map(String.init)
        }
        if chain.isEmpty {
            chain = ["https://dns.adguard-dns.com/dns-query",
                     "https://family.adguard-dns.com/dns-query"]
        }
        dohEndpoints = chain.compactMap { raw in
            guard let url = URL(string: raw), url.scheme == "https", let host = url.host else { return nil }
            return (host, url)
        }
        if !dohEndpoints.isEmpty {
            NSLog("[CleanGEOVPN] DoH chain: %@", dohEndpoints.map { $0.host }.joined(separator: " → "))
        }

        // The tunnel's internal address — DNS is answered here.
        let dnsAddr = (pc["dns"] as? String).map {
            String($0.split(separator: ",").first ?? Substring("10.111.222.1"))
        } ?? "10.111.222.1"
        let mtu = (pc["mtu"] as? NSNumber)?.intValue ?? 1420

        // 3) Network settings. Routes include ONLY the tunnel's own DNS
        // address: real internet traffic keeps using the physical interface,
        // while all DNS queries are routed into the tunnel and leave the
        // device only as encrypted DoH. This is what makes the tunnel local.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: dnsAddr)
        settings.mtu = NSNumber(value: mtu)

        let ipv4 = NEIPv4Settings(addresses: [dnsAddr], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: dnsAddr,
                                           subnetMask: "255.255.255.255")]
        settings.ipv4Settings = ipv4

        // No IPv6 route is claimed: IPv6 DNS is handled by iOS preferring the
        // tunnel's DNS resolver (matchDomains "" below).
        let dns = NEDNSSettings(servers: [dnsAddr])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                completionHandler(error)
                return
            }
            self.observePackets()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        flowReadActive = false
        dnsSession?.invalidateAndCancel()
        dnsSession = nil
        completionHandler()
    }

    // MARK: - Packet I/O

    private func observePackets() {
        flowReadActive = true
        packetFlow.readPackets { [weak self] packets, versions in
            guard let self, self.flowReadActive else { return }
            for (i, pkt) in packets.enumerated() {
                self.handlePacket(pkt, version: versions[i])
            }
            self.observePackets()
        }
    }

    private func handlePacket(_ packet: Data, version: NSNumber) {
        guard packet.count >= 28, version.intValue == 4 else { return }
        let base = packet.startIndex
        let ihl = Int(packet[base] & 0x0F) * 4
        guard packet.count > ihl + 8 else { return }
        // UDP only: the tunnel routes nothing else.
        guard packet[base + 9] == 17 else { return }
        let dstPort = (Int(packet[base + ihl + 2]) << 8) | Int(packet[base + ihl + 3])
        guard dstPort == 53 else { return } // only DNS enters the tunnel
        handleDNSPacket(packet, ihl: ihl)
    }

    // MARK: - DNS handling

    private func handleDNSPacket(_ packet: Data, ihl: Int) {
        guard packet.count >= ihl + 20 else { return }
        let base = packet.startIndex
        let srcIP = packet.subdata(in: (base + 12)..<(base + 16))
        let udpBase = base + ihl
        let srcPort = (Int(packet[udpBase]) << 8) | Int(packet[udpBase + 1])
        let dstPort = (Int(packet[udpBase + 2]) << 8) | Int(packet[udpBase + 3])
        let dnsData = packet.subdata(in: (udpBase + 8)..<packet.count)
        guard dnsData.count >= 12 else { return }

        let id = (UInt16(dnsData[dnsData.startIndex]) << 8) |
                 UInt16(dnsData[dnsData.startIndex + 1])
        let qname = Self.extractQName(dnsData, offset: 12)

        // Blocklist check — the same list Safari blocks with.
        if let bl = blocklist, !qname.isEmpty, bl.isBlocked(qname) {
            sendDNSResponse(Self.blockedResponse(id: id, qname: qname),
                            toIP: srcIP, fromPort: dstPort, toPort: srcPort)
            return
        }

        // Forward through the DoH chain with automatic fallback.
        resolveOverDoH(dnsData) { [weak self] data in
            guard let self, let data else { return }
            self.sendDNSResponse(data, toIP: srcIP, fromPort: dstPort, toPort: srcPort)
        }
    }

    /// Tries the DoH endpoints in order; on success remembers the working one.
    private func resolveOverDoH(_ dnsQuery: Data, completion: @escaping (Data?) -> Void) {
        guard !dohEndpoints.isEmpty else { completion(nil); return }
        tryEndpoint(at: activeEndpointIndex, query: dnsQuery) { [weak self] data in
            guard let self else { completion(nil); return }
            if data != nil {
                completion(data)
            } else if self.activeEndpointIndex + 1 < self.dohEndpoints.count {
                // Primary is unreachable — fall over automatically.
                NSLog("[CleanGEOVPN] %@ არ პასუხობს, გადადის fallback-ზე",
                      self.dohEndpoints[self.activeEndpointIndex].host)
                self.activeEndpointIndex += 1
                self.resolveOverDoH(dnsQuery, completion: completion)
            } else {
                // Whole chain failed; start from the primary next time.
                self.activeEndpointIndex = 0
                completion(nil)
            }
        }
    }

    private func tryEndpoint(at index: Int, query: Data, completion: @escaping (Data?) -> Void) {
        guard index < dohEndpoints.count else { completion(nil); return }
        let ep = dohEndpoints[index]

        let session = dnsSession ?? makeSession()
        dnsSession = session

        var req = URLRequest(url: ep.url)
        req.httpMethod = "POST"
        req.timeoutInterval = 8
        req.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        req.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        req.httpBody = query

        session.dataTask(with: req) { data, response, error in
            if let error {
                NSLog("[CleanGEOVPN] DoH %@ შეცდომა: %@", ep.host, error.localizedDescription)
                completion(nil)
                return
            }
            guard let http = response as? HTTPURLResponse,
                  (200..<300).contains(http.statusCode),
                  let data, data.count >= 12,
                  data[data.startIndex] == query[query.startIndex],
                  data[data.startIndex + 1] == query[query.startIndex + 1] else {
                NSLog("[CleanGEOVPN] DoH %@ დააბრუნა არასწორი პასუხი", ep.host)
                completion(nil)
                return
            }
            completion(data)
        }.resume()
    }

    private func makeSession() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 8
        cfg.timeoutIntervalForResource = 16
        cfg.tlsMinimumSupportedProtocolVersion = .TLSv12
        return URLSession(configuration: cfg)
    }

    private func sendDNSResponse(_ dnsData: Data, toIP: Data, fromPort: Int, toPort: Int) {
        var pkt = Data()
        pkt.append(0x45)
        pkt.append(0x00)
        let totalLen = 20 + 8 + dnsData.count
        pkt.append(UInt8((totalLen >> 8) & 0xFF))
        pkt.append(UInt8(totalLen & 0xFF))
        pkt.append(contentsOf: [0x00, 0x00, 0x40, 0x11, 0x00, 0x00]) // TTL 64, proto UDP, cksum 0
        pkt.append(10); pkt.append(0); pkt.append(111); pkt.append(222) // tunnel DNS address
        pkt.append(contentsOf: toIP)
        pkt.append(UInt8((fromPort >> 8) & 0xFF))
        pkt.append(UInt8(fromPort & 0xFF))
        pkt.append(UInt8((toPort >> 8) & 0xFF))
        pkt.append(UInt8(toPort & 0xFF))
        let udpLen = 8 + dnsData.count
        pkt.append(UInt8((udpLen >> 8) & 0xFF))
        pkt.append(UInt8(udpLen & 0xFF))
        pkt.append(contentsOf: [0x00, 0x00])
        pkt.append(dnsData)
        packetFlow.writePackets([pkt], withProtocols: [NSNumber(value: 2)]) // 2 = AF_INET
    }

    // MARK: - Helpers

    static func extractQName(_ data: Data, offset: Int) -> String {
        var labels: [String] = []
        var i = data.startIndex + offset
        while i < data.endIndex {
            let len = Int(data[i])
            if len == 0 || (len & 0xC0) != 0 { break }
            guard i + 1 + len <= data.endIndex else { break }
            let label = String(data: data.subdata(in: (i + 1)..<(i + 1 + len)),
                               encoding: .utf8) ?? ""
            labels.append(label)
            i += 1 + len
        }
        return labels.joined(separator: ".")
    }

    /// A-record 0.0.0.0 answer for blocked domains.
    static func blockedResponse(id: UInt16, qname: String) -> Data {
        var d = Data()
        d.append(UInt8(id >> 8)); d.append(UInt8(id & 0xFF))
        d.append(contentsOf: [0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
        for label in qname.split(separator: ".") {
            d.append(UInt8(label.count))
            d.append(contentsOf: label.utf8)
        }
        d.append(0x00)
        d.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A IN
        d.append(contentsOf: [0xC0, 0x0C])             // pointer to QNAME
        d.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        d.append(contentsOf: [0x00, 0x00, 0x00, 0x3C]) // TTL 60
        d.append(contentsOf: [0x00, 0x04])
        d.append(contentsOf: [0, 0, 0, 0])             // 0.0.0.0
        return d
    }
}
