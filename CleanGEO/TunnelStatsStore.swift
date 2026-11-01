//
//  TunnelStatsStore.swift
//  CleanGEO
//
//  ტუნელის მიერ App Group-ში შენახული სტატისტიკის წაკითხვა (Filters/dns-stats.json)
//  და კატეგორიების რუკის გამოქვეყნება (Filters/dns-categories.json).
//  ყველაფერი ლოკალურია — მონაცემები მოწყობილობიდან არ გადის.
//

import Foundation

/// ტუნელის სტატისტიკის ფაილის მოდელი — ზუსტად ის, რასაც
/// CleanGEOVPN-ის PacketTunnelProvider წერს.
public struct TunnelStatsFile: Codable, Equatable {
    public struct Day: Codable, Equatable {
        public var day: String
        public var queries: Int
        public var blocked: Int
    }
    public struct Top: Codable, Equatable {
        public var host: String
        public var count: Int
    }

    public var queries: Int = 0
    public var blocked: Int = 0
    public var ads: Int = 0
    public var trackers: Int = 0
    public var bytesUp: Int64 = 0
    public var bytesDown: Int64 = 0
    public var days: [Day] = []
    public var top: [Top] = []

    public init() {}
}

public enum TunnelStatsStore {

    static var appGroupID = "group.87486bbbb00f533a.3"
    static var statsPath = "Filters/dns-stats.json"
    static var categoriesPath = "Filters/dns-categories.json"

    /// წინა კვირის დღიური მონაცემები (7 ელემენტი, ორშ→კვ) — აქტივობის გრაფიკისთვის.
    public static func loadWeek() -> [Int] {
        let s = load()
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd"
        fmt.timeZone = TimeZone(identifier: "UTC")
        fmt.locale = Locale(identifier: "en_US_POSIX")
        let cal = Calendar(identifier: .gregorian)
        let today = fmt.string(from: Date())

        var result = [Int](repeating: 0, count: 7)
        // ISO კვირა: ორშაბათი = 2 … კვირა = 1
        for day in s.days {
            guard let d = fmt.date(from: day.day),
                  let idx = cal.dateComponents([.weekday], from: d).weekday.map({ idx(of: $0) }) else { continue }
            let dayStr = fmt.string(from: d)
            _ = dayStr; _ = today
            result[idx] += day.queries
        }
        return result
    }

    static func idx(of weekday: Int) -> Int {
        // weekday: 1=კვირა, 2=ორშაბათი … 7=შაბათი → ინდექსი ორშ=0 … კვ=6
        (weekday + 5) % 7
    }

    /// დღევანდელი დღის სტატისტიკა ცალკე (საჭიროების შემთხვევაში).
    public static func today() -> (queries: Int, blocked: Int)? {
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd"
        fmt.timeZone = TimeZone(identifier: "UTC")
        fmt.locale = Locale(identifier: "en_US_POSIX")
        let t = fmt.string(from: Date())
        let s = load()
        guard let d = s.days.first(where: { $0.day == t }) else { return nil }
        return (d.queries, d.blocked)
    }

    public static func load() -> TunnelStatsFile {
        guard let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID),
              let data = try? Data(contentsOf: container.appendingPathComponent(statsPath)),
              let decoded = try? JSONDecoder().decode(TunnelStatsFile.self, from: data) else {
            return TunnelStatsFile()
        }
        return decoded
    }

    /// დღიური სიის არქივი 8 დღეზე მეტს არ ინახავს — ტუნელი თვითონ წმენდს.
    public static func pruneDays(_ days: [TunnelStatsFile.Day]) -> [TunnelStatsFile.Day] {
        guard days.count > 8 else { return days }
        return Array(days.suffix(8))
    }

    // MARK: - კატეგორიების რუკა (აპი წერს, ტუნელი კითხულობს)

    /// ფილტრ-სიებიდან აგებს დომენი→კატეგორია რუკას: თრექერების სიის დომენები
    /// "trackers", დანარჩენი "ads". ტუნელი ამ ფაილს კითხულობს დაბლოკვის
    /// კატეგორიის გასარკვევად.
    public static func publishCategories(sources: [FilterListSource]) {
        guard let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else { return }
        var map: [String: String] = [:]
        let fm = FileManager.default
        let staging = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Filters/staging", isDirectory: true)
        for src in sources where src.enabled && src.id.contains("tracking") {
            let rawURL = staging.appendingPathComponent("\(src.id).txt")
            guard let text = try? String(contentsOf: rawURL, encoding: .utf8) else { continue }
            for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
                let l = line.trimmingCharacters(in: .whitespaces)
                if l.hasPrefix("!") || l.hasPrefix("[") || l.hasPrefix("#") || l.hasPrefix("@@") { continue }
                if l.contains("#") { continue }
                var d = l
                if d.hasPrefix("||") { d = String(d.dropFirst(2)) } else if d.hasPrefix("|") { d = String(d.dropFirst(1)) }
                if let dollar = d.range(of: "$") { d = String(d[..<dollar.lowerBound]) }
                if d.hasSuffix("^") { d = String(d.dropLast()) }
                if d.hasSuffix("^|") { d = String(d.dropLast(2)) }
                d = d.trimmingCharacters(in: CharacterSet(charactersIn: "^|/"))
                guard d.contains("."), !d.contains(" "),
                      d.count >= 4, d.count <= 253 else { continue }
                map[d.lowercased()] = "trackers"
            }
        }
        let dir = container.appendingPathComponent("Filters", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(map) {
            try? data.write(to: dir.appendingPathComponent(categoriesPath), options: .atomic)
        }
    }

    /// სტატისტიკის გასუფთავება აპიდან: ფაილს ცარიელი მნიშვნელობით ანაცვლებს.
    /// ტუნელი 5 წამში ერთხელ წერს და შემდეგ flush-ზე ხელახლა წაიკითხავს —
    /// ამიტომ გასუფთავება აქტიური ტუნელისას დროებითია; სრული გასუფთავება
    /// ტუნელის გამორთვისას ხდება.
    public static func clear() {
        guard let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else { return }
        let empty = try? JSONEncoder().encode(TunnelStatsFile())
        if let empty {
            try? empty.write(to: container.appendingPathComponent(statsPath), options: .atomic)
        }
    }
}
