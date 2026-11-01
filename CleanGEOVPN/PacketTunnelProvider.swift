//
//  PacketTunnelProvider.swift
//  CleanGEOVPN
//
//  ლოკალური პრივატული ტუნელი — AdGuard Pro-ს სქემა:
//
//    1. iOS ყველა DNS-მოთხოვნას ამისამართებს ტუნელს (matchDomains "")
//    2. ტუნელი ამოწმებს ბლოკლისტს — იგივე კომპილირებული სია, რასაც Safari
//       ბლოკავს (App Group: Filters/cleangeo-blocker.json):
//         A     → პასუხი 0.0.0.0
//         AAAA  → ცარიელი პასუხი (NOERROR, 0 ჩანაწერი)
//         სხვა  → ცარიელი პასუხი
//    3. დაუბლოკელი მოთხოვნა მიდის DoH ჯაჭვზე:
//         1) https://dns.adguard-dns.com/dns-query      (პირველადი)
//         2) https://family.adguard-dns.com/dns-query   (ავტომატური fallback)
//       ჯაჭვი თვითონ გადადის სარეზერვოზე და იმახსოვრებს მომუშავეს.
//    4. სტატისტიკა (მოთხოვნები, დაბლოკვები, კატეგორიები, ტოპ-დომენები,
//       ტრაფიკი) ინახება App Group-ში (Filters/dns-stats.json) — აპი კითხულობს.
//
//  გარეთ გადის მხოლოდ დაშიფრული HTTPS (DoH). სერვერზე კავშირი არ დგინდება,
//  ტრაფიკი ტუნელს არ გადის — მარშრუტი მხოლოდ ტუნელის DNS-მისამართზეა.
//

import NetworkExtension
import Foundation

final class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - კონსტანტები

    static let appGroup = "group.87486bbbb00f533a.3"
    static let statsFilePath = "Filters/dns-stats.json"
    static let categoriesFilePath = "Filters/dns-categories.json"
    static let defaultChain = ["https://dns.adguard-dns.com/dns-query",
                               "https://family.adguard-dns.com/dns-query"]

    // MARK: - ბლოკლისტი (იგივე JSON, რაც Safari-ს კონტენტ-ბლოკერს)

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
                .containerURL(forSecurityApplicationGroupIdentifier: PacketTunnelProvider.appGroup) else { return }
            let url = container.appendingPathComponent("Filters", isDirectory: true)
                .appendingPathComponent("cleangeo-blocker.json")
            guard let data = try? Data(contentsOf: url),
                  let rules = try? JSONDecoder().decode([TunneledRule].self, from: data) else { return }
            var b: Set<String> = []
            var a: Set<String> = []
            for r in rules {
                guard let f = r.trigger?.urlFilter, !f.isEmpty else { continue }
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

    /// დომენის კატეგორია სტატისტიკისთვის: "ads" | "trackers".
    /// აპი წერს თითოეული ფილტრ-სიის დომენებს — თრექერების სიიდან მოსული
    /// დომენი "trackers"-ად ითვლება, დანარჩენი "ads"-ად.
    private final class LocalCategories {
        private var map: [String: String] = [:]
        private let lock = NSLock()

        func load() {
            guard let container = FileManager.default
                .containerURL(forSecurityApplicationGroupIdentifier: PacketTunnelProvider.appGroup) else { return }
            let url = container.appendingPathComponent(PacketTunnelProvider.categoriesFilePath)
            guard let data = try? Data(contentsOf: url),
                  let decoded = try? JSONDecoder().decode([String: String].self, from: data) else { return }
            lock.lock()
            map = decoded
            lock.unlock()
        }

        func category(of host: String) -> String {
            lock.lock(); defer { lock.unlock() }
            var h = host.lowercased()
            while h.contains(".") {
                if let c = map[h] { return c }
                let parts = h.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
                guard parts.count == 2 else { break }
                h = String(parts[1])
            }
            return "ads"
        }
    }

    // MARK: - სტატისტიკა (ინახება App Group-ში, კითხულობს აპი)

    struct TunnelStats: Codable {
        struct Day: Codable { var day: String; var queries: Int; var blocked: Int }
        struct Top: Codable { var host: String; var count: Int }
        var queries: Int = 0
        var blocked: Int = 0
        var ads: Int = 0
        var trackers: Int = 0
        var bytesUp: Int64 = 0
        var bytesDown: Int64 = 0
        var days: [Day] = []
        var top: [Top] = []
    }

    private final class StatsCounter {
        private var stats = TunnelStats()
        private let lock = NSLock()
        private let queue = DispatchQueue(label: "cleangeo.stats.flush")
        private var timer: DispatchSourceTimer?
        private let fileURL: URL?

        private static let dayFormatter: DateFormatter = {
            let f = DateFormatter()
            f.dateFormat = "yyyy-MM-dd"
            f.timeZone = TimeZone(identifier: "UTC")
            f.locale = Locale(identifier: "en_US_POSIX")
            return f
        }()

        init() {
            fileURL = FileManager.default
                .containerURL(forSecurityApplicationGroupIdentifier: PacketTunnelProvider.appGroup)?
                .appendingPathComponent(PacketTunnelProvider.statsFilePath)
            stats = Self.read(fileURL) ?? TunnelStats()
        }

        func startAutoFlush() {
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now() + 5, repeating: 5.0)
            t.setEventHandler { [weak self] in self?.flush() }
            t.resume()
            timer = t
        }

        func stop() {
            timer?.cancel()
            timer = nil
            flush()
        }

        /// თითოეული DNS-მოთხოვნა: ბაიტები + დღიური აღრიცხვა (დაბლოკვის გარეშე).
        func recordQuery(host: String, queryBytes: Int) {
            lock.lock(); defer { lock.unlock() }
            let today = Self.dayFormatter.string(from: Date())
            stats.queries += 1
            stats.bytesUp += Int64(queryBytes)
            bumpDay(today) { $0.queries += 1 }
        }

        /// დაბლოკვის აღრიცხვა: ჯამი, კატეგორია, ტოპ-დომენები, დღიური.
        func recordBlock(host: String) {
            lock.lock(); defer { lock.unlock() }
            bumpDay(Self.dayFormatter.string(from: Date())) { $0.blocked += 1 }
            stats.blocked += 1
            if categories?.category(of: host) == "trackers" {
                stats.trackers += 1
            } else {
                stats.ads += 1
            }
            if let i = stats.top.firstIndex(where: { $0.host == host }) {
                stats.top[i].count += 1
            } else {
                stats.top.append(Top(host: host, count: 1))
            }
            stats.top.sort { $0.count > $1.count }
            if stats.top.count > 10 { stats.top.removeLast(stats.top.count - 10) }
        }

        private func bumpDay(_ today: String, _ inc: (inout Day) -> Void) {
            if let i = stats.days.firstIndex(where: { $0.day == today }) {
                inc(&stats.days[i])
            } else {
                var d = Day(day: today, queries: 0, blocked: 0)
                inc(&d)
                stats.days.append(d)
                if stats.days.count > 8 { stats.days.removeFirst(stats.days.count - 8) }
            }
        }

        func recordResponse(bytes: Int) {
            lock.lock(); defer { lock.unlock() }
            stats.bytesDown += Int64(bytes)
        }

        func reset() {
            lock.lock()
            stats = TunnelStats()
            lock.unlock()
            flush()
        }

        private var lastWrite = Date(timeIntervalSince1970: 0)

        func flush() {
            lock.lock()
            let snapshot = stats
            lock.unlock()
            guard let url = fileURL else { return }
            // აპიდან გასუფთავების აღქმა: თუ ფაილი ჩვენს ბოლო ჩაწერაზე ახალია
            // და შიგნით მცირე ჯამებია — გარე გასუფთავებაა, ვიღებთ მის მნიშვნელობებს.
            if lastWrite.timeIntervalSince1970 > 0,
               let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
               let mtime = attrs[.modificationDate] as? Date,
               mtime > lastWrite,
               let external = Self.read(url), external.queries < snapshot.queries {
                lock.lock()
                stats = external
                lock.unlock()
                lastWrite = Date()
                return
            }
            guard let data = try? JSONEncoder().encode(snapshot) else { return }
            try? data.write(to: url, options: .atomic)
            lastWrite = Date()
        }

        static func read(_ url: URL?) -> TunnelStats? {
            guard let url, let data = try? Data(contentsOf: url) else { return nil }
            return try? JSONDecoder().decode(TunnelStats.self, from: data)
        }
    }

    // MARK: - მდგომარეობა

    private var blocklist = LocalBlocklist()
    private var categories: LocalCategories?
    private var stats: StatsCounter?
    private var dohEndpoints: [(host: String, url: URL)] = []
    private var activeEndpointIndex = 0
    private var dnsSession: URLSession?
    private var flowReadActive = false
    /// ტუნელის შიდა DNS-მისამართი — პასუხი სწორედ აქედან უნდა მოდიოდეს.
    private var tunnelDNSAddr: [UInt8] = [10, 111, 222, 1]

    // MARK: - ტუნელის ციკლი

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        // 1) ბლოკლისტი და კატეგორიები App Group-იდან.
        blocklist.load()
        let cats = LocalCategories()
        cats.load()
        categories = cats

        // 2) სტატისტიკა: წინა მნიშვნელობები ინახება (ფაილიდან იკითხება).
        let counter = StatsCounter()
        counter.startAutoFlush()
        stats = counter

        // 3) providerConfiguration, რომელსაც აპი წერს.
        let cfg = protocolConfiguration as? NETunnelProviderProtocol
        let pc = cfg?.providerConfiguration as? [String: Any] ?? [:]

        var chain: [String] = []
        if let provided = pc["dohChain"] as? String {
            chain = provided.split(separator: " ").map(String.init)
        }
        if chain.isEmpty {
            chain = Self.defaultChain
        }
        dohEndpoints = chain.compactMap { raw in
            guard let url = URL(string: raw), url.scheme == "https", let host = url.host else { return nil }
            return (host, url)
        }
        NSLog("[CleanGEOVPN] DoH ჯაჭვი: %@", dohEndpoints.map { $0.host }.joined(separator: " → "))

        // ტუნელის შიდა DNS-მისამართი (პასუხები ამ IP-დან მიდის).
        if let dnsStr = pc["dns"] as? String {
            let first = String(dnsStr.split(separator: ",").first ?? Substring("10.111.222.1"))
            let octets = first.split(separator: ".").compactMap { UInt8($0) }
            if octets.count == 4 { tunnelDNSAddr = octets }
        }
        let dnsAddr = tunnelDNSAddr.map(String.init).joined(separator: ".")
        let mtu = (pc["mtu"] as? NSNumber)?.intValue ?? 1420

        // 4) ქსელის პარამეტრები. მარშრუტი მხოლოდ ტუნელის DNS-მისამართზეა:
        //    რეალური ტრაფიკი ფიზიკურ ინტერფეისს იყენებს, ტუნელში მხოლოდ
        //    DNS შედის და გარეთ მხოლოდ დაშიფრული DoH გადის.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: dnsAddr)
        settings.mtu = NSNumber(value: mtu)

        let ipv4 = NEIPv4Settings(addresses: [dnsAddr], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: dnsAddr,
                                           subnetMask: "255.255.255.255")]
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: [dnsAddr])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                counter.stop()
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
        stats?.stop()
        dnsSession?.invalidateAndCancel()
        dnsSession = nil
        completionHandler()
    }

    /// სტატისტიკის გასუფთავება აპიდან (მომავალი XPC-სთვის დაცული გზა:
    /// აპი ფაილს ცარიელით ანაცვლებს, ტუნელი შემდეგ გაშვებაზე წაიკითხავს).

    // MARK: - პაკეტების წაკითხვა

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
        // მხოლოდ UDP შედის ტუნელში.
        guard packet[base + 9] == 17 else { return }
        let dstPort = (Int(packet[base + ihl + 2]) << 8) | Int(packet[base + ihl + 3])
        guard dstPort == 53 else { return }
        handleDNSPacket(packet, ihl: ihl)
    }

    // MARK: - DNS

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
        let question = Self.parseQuestion(dnsData)
        let qname = question.name
        let qtype = question.type

        // სტატისტიკა: ყველა მოთხოვნა ითვლება.
        stats?.recordQuery(host: qname, queryBytes: dnsData.count)

        // ბლოკლისტი — იგივე სია, რასაც Safari ბლოკავს.
        if !qname.isEmpty, blocklist.isBlocked(qname) {
            let answer = Self.blockedResponse(id: id, qname: qname, qtype: qtype)
            sendDNSResponse(answer, toIP: srcIP, fromPort: dstPort, toPort: srcPort)
            stats?.recordBlock(host: qname)
            stats?.recordResponse(bytes: answer.count)
            return
        }

        // გადაგზავნა DoH ჯაჭვზე ავტო-fallback-ით.
        resolveOverDoH(dnsData) { [weak self] data in
            guard let self else { return }
            if let data {
                self.sendDNSResponse(data, toIP: srcIP, fromPort: dstPort, toPort: srcPort)
                self.stats?.recordResponse(bytes: data.count)
            } else {
                // მთელი ჯაჭვი ჩავარდა — SERVFAIL, რომ კლიენტმა 8 წამი არ დაიცადოს.
                let fail = Self.failResponse(id: id, qname: qname, qtype: qtype)
                self.sendDNSResponse(fail, toIP: srcIP, fromPort: dstPort, toPort: srcPort)
                self.stats?.recordResponse(bytes: fail.count)
            }
        }
    }

    /// ჯაჭვის თითოეული endpoint რიგით ცდის; მომუშავეს იმახსოვრებს.
    private func resolveOverDoH(_ dnsQuery: Data, completion: @escaping (Data?) -> Void) {
        guard !dohEndpoints.isEmpty else { completion(nil); return }
        tryEndpoint(at: activeEndpointIndex, query: dnsQuery) { [weak self] data in
            guard let self else { completion(nil); return }
            if data != nil {
                completion(data)
            } else if self.activeEndpointIndex + 1 < self.dohEndpoints.count {
                NSLog("[CleanGEOVPN] %@ არ პასუხობს, გადადის სარეზერვოზე",
                      self.dohEndpoints[self.activeEndpointIndex].host)
                self.activeEndpointIndex += 1
                self.resolveOverDoH(dnsQuery, completion: completion)
            } else {
                // ჯაჭვი ამოიწურა — შემდეგი მოთხოვნა პირველადიდან დაიწყება.
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

    // MARK: - IP/UDP პასუხის აწყობა

    /// პასუხი გადაეცემა ტუნელში შემომსვლელი მოთხოვნის მიმართულებით:
    /// წყარო — ტუნელის DNS-მისამართი (ის, რომელზეც მოთხოვნა გაიგზავნა),
    /// მიმღები — სისტემის რეზოლვერის პორტი.
    private func sendDNSResponse(_ dnsData: Data, toIP: Data, fromPort: Int, toPort: Int) {
        let totalLen = 20 + 8 + dnsData.count
        guard totalLen <= 0xFFFF, toIP.count == 4 else { return }

        // IPv4 ჰედერი (20 ბაიტი): ver/IHL, TOS, სიგრძე, ID, flags(DF),
        // TTL 64, proto UDP, ჩეკსამი (ქვემოთ ითვლება).
        var hdr: [UInt8] = [0x45, 0x00,
                            UInt8((totalLen >> 8) & 0xFF), UInt8(totalLen & 0xFF),
                            0x00, 0x00,                 // identification
                            0x40, 0x00,                 // flags: Don't Fragment
                            0x40, 0x11,                 // TTL 64, proto UDP (17)
                            0x00, 0x00]                 // checksum (placeholder)
        hdr.append(contentsOf: tunnelDNSAddr)   // წყარო: ტუნელის DNS
        hdr.append(contentsOf: Array(toIP))     // მიმღები
        let sum = Self.ipChecksum(hdr)
        hdr[10] = UInt8((sum >> 8) & 0xFF)
        hdr[11] = UInt8(sum & 0xFF)

        var pkt = Data(hdr)
        let udpLen = 8 + dnsData.count
        pkt.append(UInt8((fromPort >> 8) & 0xFF))   // 53 — DNS
        pkt.append(UInt8(fromPort & 0xFF))
        pkt.append(UInt8((toPort >> 8) & 0xFF))
        pkt.append(UInt8(toPort & 0xFF))
        pkt.append(UInt8((udpLen >> 8) & 0xFF))
        pkt.append(UInt8(udpLen & 0xFF))
        pkt.append(contentsOf: [0x00, 0x00])        // UDP checksum 0 (IPv4-ში დასაშვებია)
        pkt.append(dnsData)
        packetFlow.writePackets([pkt], withProtocols: [NSNumber(value: 2)]) // 2 = AF_INET
    }

    /// IPv4 ჰედერის ჩეკსამი.
    static func ipChecksum(_ hdr: [UInt8]) -> UInt16 {
        var sum = 0
        var i = 0
        while i < hdr.count {
            let high = Int(hdr[i]) << 8
            let low = i + 1 < hdr.count ? Int(hdr[i + 1]) : 0
            sum += high | low
            i += 2
        }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return UInt16(~sum & 0xFFFF)
    }

    // MARK: - DNS დამხმარეები

    /// QNAME + QTYPE-ის ამოღება მოთხოვნიდან.
    static func parseQuestion(_ data: Data) -> (name: String, type: UInt16) {
        var labels: [String] = []
        var i = data.startIndex + 12
        while i < data.endIndex {
            let len = Int(data[i])
            if len == 0 || (len & 0xC0) != 0 { i += 1; break }
            guard i + 1 + len <= data.endIndex else { break }
            let label = String(data: data.subdata(in: (i + 1)..<(i + 1 + len)),
                               encoding: .utf8) ?? ""
            labels.append(label)
            i += 1 + len
        }
        guard i + 2 <= data.endIndex else { return (labels.joined(separator: "."), 1) }
        let t = (UInt16(data[i]) << 8) | UInt16(data[i + 1])
        return (labels.joined(separator: "."), t)
    }

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

    /// დაბლოკილი დომენის პასუხი: A → 0.0.0.0; AAAA/სხვა → ცარიელი NOERROR.
    static func blockedResponse(id: UInt16, qname: String, qtype: UInt16) -> Data {
        var d = Data()
        d.append(UInt8(id >> 8)); d.append(UInt8(id & 0xFF))
        d.append(contentsOf: [0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        appendQuestion(&d, qname: qname, qtype: qtype)
        if qtype == 1 {
            d.append(contentsOf: [0xC0, 0x0C])             // pointer to QNAME
            d.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A IN
            d.append(contentsOf: [0x00, 0x00, 0x00, 0x3C]) // TTL 60
            d.append(contentsOf: [0x00, 0x04])
            d.append(contentsOf: [0, 0, 0, 0])             // 0.0.0.0
            // ancount გამოსწორებული
            d[7] = 0x01
        }
        return d
    }

    /// ჯაჭვის სრული ჩავარდნის პასუხი: SERVFAIL, რომ კლიენტმა სწრაფად სცადოს თავიდან.
    static func failResponse(id: UInt16, qname: String, qtype: UInt16) -> Data {
        var d = Data()
        d.append(UInt8(id >> 8)); d.append(UInt8(id & 0xFF))
        d.append(contentsOf: [0x81, 0x82, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        appendQuestion(&d, qname: qname, qtype: qtype)
        return d
    }

    private static func appendQuestion(_ d: inout Data, qname: String, qtype: UInt16) {
        for label in qname.split(separator: ".") {
            d.append(UInt8(min(label.count, 63)))
            d.append(contentsOf: label.utf8.prefix(63))
        }
        d.append(0x00)
        d.append(UInt8(qtype >> 8)); d.append(UInt8(qtype & 0xFF))
        d.append(contentsOf: [0x00, 0x01]) // IN
    }
}
