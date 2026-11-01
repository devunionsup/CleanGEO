import NetworkExtension
import Foundation

/// Local DNS tunnel: only the virtual DNS address is routed into the tunnel.
/// Blocked names are answered on-device; everything else goes out via DoH.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let dnsIP = "10.111.222.1"
    private let doh = DoHClient()
    private let queue = DispatchQueue(label: "cleangeo.tunnel.stats")
    private var blocked: [String: String] = [:]   // domain -> "a" | "t"
    private var allowed = Set<String>()
    private var stats = DNSStats.load()
    private var lastFlush = Date.distantPast

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        loadBlocklist()
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: dnsIP)
        let v4 = NEIPv4Settings(addresses: ["10.111.222.2"], subnetMasks: ["255.255.255.255"])
        v4.includedRoutes = [NEIPv4Route(destinationAddress: dnsIP, subnetMask: "255.255.255.255")]
        s.ipv4Settings = v4
        let dns = NEDNSSettings(servers: [dnsIP])
        dns.matchDomains = [""]                    // all domains
        s.dnsSettings = dns
        s.mtu = 1400
        setTunnelNetworkSettings(s) { [weak self] err in
            if err == nil { self?.readLoop() }
            completionHandler(err)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.sync { stats.save() }
        completionHandler()
    }

    // MARK: blocklist
    private func loadBlocklist() {
        guard let text = try? String(contentsOf: AppGroup.domainList, encoding: .utf8) else { return }
        for line in text.split(separator: "\n") {
            let p = line.split(separator: "\t", maxSplits: 1)
            guard p.count == 2 else { continue }
            let d = String(p[1])
            if p[0] == "@" { allowed.insert(d) } else { blocked[d] = String(p[0]) }
        }
    }

    /// Returns category if the name (or a parent domain) is blocked and not allow-listed.
    private func match(_ name: String) -> String? {
        var parts = name.split(separator: ".").map(String.init)
        var cat: String?
        while parts.count >= 2 {
            let d = parts.joined(separator: ".")
            if allowed.contains(d) { return nil }
            if cat == nil, let c = blocked[d] { cat = c }
            parts.removeFirst()
        }
        return cat
    }

    // MARK: packets
    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self else { return }
            for p in packets { self.handle(p) }
            self.readLoop()
        }
    }

    private func handle(_ packet: Data) {
        guard let ip = UDPPacket(packet), ip.dstPort == 53,
              let q = DNSWire.parseQuestion(ip.payload) else { return }
        if let cat = match(q.name) {
            reply(ip, DNSWire.blockedResponse(for: ip.payload, q: q))
            record(q.name, blockedCategory: cat, bytes: packet.count)
        } else {
            doh.resolve(ip.payload) { [weak self] data in
                guard let self = self else { return }
                if let data = data { self.reply(ip, data) }
                self.record(q.name, blockedCategory: nil, bytes: packet.count + (data?.count ?? 0))
            }
        }
    }

    private func reply(_ req: UDPPacket, _ dns: Data) {
        packetFlow.writePackets([req.makeReply(dns)], withProtocols: [NSNumber(value: AF_INET)])
    }

    private func record(_ name: String, blockedCategory: String?, bytes: Int) {
        queue.async {
            let day = DNSStats.dayKey()
            self.stats.total += 1
            self.stats.bytes += Int64(bytes)
            var d = self.stats.daily[day] ?? DayStat()
            d.total += 1
            if let c = blockedCategory {
                self.stats.blocked += 1; d.blocked += 1
                if c == "t" { self.stats.trackers += 1 } else { self.stats.ads += 1 }
                self.stats.top[name, default: 0] += 1
            }
            self.stats.daily[day] = d
            if Date().timeIntervalSince(self.lastFlush) > 2 {
                self.lastFlush = Date(); self.stats.save()
            }
        }
    }
}

/// IPv4 + UDP packet parser / reply builder.
struct UDPPacket {
    let src: [UInt8], dst: [UInt8]
    let srcPort: UInt16, dstPort: UInt16
    let payload: Data

    init?(_ data: Data) {
        let b = [UInt8](data)
        guard b.count >= 28, b[0] >> 4 == 4, b[9] == 17 else { return nil }
        let ihl = Int(b[0] & 0x0F) * 4
        guard ihl >= 20, b.count >= ihl + 8 else { return nil }
        src = Array(b[12..<16]); dst = Array(b[16..<20])
        srcPort = UInt16(b[ihl]) << 8 | UInt16(b[ihl + 1])
        dstPort = UInt16(b[ihl + 2]) << 8 | UInt16(b[ihl + 3])
        let len = Int(b[ihl + 4]) << 8 | Int(b[ihl + 5])
        guard len >= 8, b.count >= ihl + len else { return nil }
        payload = Data(b[(ihl + 8)..<(ihl + len)])
    }

    func makeReply(_ dns: Data) -> Data {
        let udpLen = 8 + dns.count, total = 20 + udpLen
        var h: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xFF), 0, 0, 0x40, 0, 64, 17, 0, 0]
        h += dst; h += src                       // swap addresses
        var sum: UInt32 = 0
        for i in stride(from: 0, to: 20, by: 2) { sum += UInt32(h[i]) << 8 | UInt32(h[i + 1]) }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        let c = ~UInt16(sum & 0xFFFF)
        h[10] = UInt8(c >> 8); h[11] = UInt8(c & 0xFF)
        var u: [UInt8] = [UInt8(dstPort >> 8), UInt8(dstPort & 0xFF),
                          UInt8(srcPort >> 8), UInt8(srcPort & 0xFF),
                          UInt8(udpLen >> 8), UInt8(udpLen & 0xFF), 0, 0]   // UDP checksum 0 is legal on IPv4
        u += dns
        return Data(h + u)
    }
}
