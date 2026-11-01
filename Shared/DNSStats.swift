import Foundation

struct DayStat: Codable { var total = 0; var blocked = 0 }

struct DNSStats: Codable {
    var total = 0
    var blocked = 0
    var ads = 0
    var trackers = 0
    var bytes: Int64 = 0
    var top: [String: Int] = [:]
    var daily: [String: DayStat] = [:]

    static func dayKey(_ d: Date = Date()) -> String {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"; f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: d)
    }

    var topTen: [(String, Int)] {
        top.sorted { $0.value > $1.value }.prefix(10).map { ($0.key, $0.value) }
    }

    static func load() -> DNSStats {
        guard let d = try? Data(contentsOf: AppGroup.statsFile),
              let s = try? JSONDecoder().decode(DNSStats.self, from: d) else { return DNSStats() }
        return s
    }
    func save() {
        if let d = try? JSONEncoder().encode(self) { try? d.write(to: AppGroup.statsFile, options: .atomic) }
    }
}
