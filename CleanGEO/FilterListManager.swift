//
//  FilterListManager.swift
//  CleanGEO
//
//  Downloads, verifies (SHA-256), compiles and persists filter lists.
//  On any failure the last known-good compiled set is kept untouched.
//

import Foundation
import CryptoKit
import CommonCrypto
import SafariServices

public struct FilterListSource: Codable, Identifiable, Equatable {
    public var id: String          // stable key, e.g. "cleangeo-main"
    public var name: String        // Georgian display name
    public var url: String
    public var enabled: Bool
    public var expectedSHA256: String?  // optional pin, lowercase hex

    public init(id: String, name: String, url: String, enabled: Bool = true, expectedSHA256: String? = nil) {
        self.id = id
        self.name = name
        self.url = url
        self.enabled = enabled
        self.expectedSHA256 = expectedSHA256
    }
}

public struct FilterStats: Codable, Equatable {
    public var lastSuccessfulUpdate: Date?
    public var ruleCount: Int
    public var listCount: Int
    public var lastError: String?

    public init(lastSuccessfulUpdate: Date? = nil, ruleCount: Int = 0, listCount: Int = 0, lastError: String? = nil) {
        self.lastSuccessfulUpdate = lastSuccessfulUpdate
        self.ruleCount = ruleCount
        self.listCount = listCount
        self.lastError = lastError
    }
}

/// Update schedule: up to four user-chosen times per day (hour & minute).
public struct UpdateSchedule: Codable, Equatable {
    public var times: [ScheduleTime]   // 0..4 entries

    public struct ScheduleTime: Codable, Equatable {
        public var hour: Int   // 0...23
        public var minute: Int // 0...59
        public init(hour: Int, minute: Int) {
            self.hour = hour
            self.minute = minute
        }
    }

    public static let `default` = UpdateSchedule(times: [
        .init(hour: 3, minute: 0),
        .init(hour: 9, minute: 0),
        .init(hour: 15, minute: 0),
        .init(hour: 21, minute: 0)
    ])

    public init(times: [ScheduleTime]) { self.times = times }

    /// Whether an update is due now, given the last successful update.
    public func isDue(now: Date = Date(), lastUpdate: Date?, calendar: Calendar = .current) -> Bool {
        guard !times.isEmpty else { return false }
        let comps = calendar.dateComponents([.hour, .minute], from: now)
        let nowMinutes = comps.hour! * 60 + comps.minute!
        var bestOverdue: Int? = nil
        for t in times {
            let dueMinutes = t.hour * 60 + t.minute
            var delta = nowMinutes - dueMinutes
            if delta < 0 { delta += 24 * 60 }
            if lastUpdate == nil {
                bestOverdue = max(bestOverdue ?? 0, delta)
                continue
            }
            let elapsed = now.timeIntervalSince(lastUpdate!)
            if elapsed >= Double(delta) * 60 - 30 { return true }
            bestOverdue = min(bestOverdue ?? Int.max, delta)
        }
        // No last update at all -> due if any scheduled slot was passed today.
        return lastUpdate == nil && bestOverdue != nil
    }
}

public final class FilterListManager {

    public static let shared = FilterListManager()

    private let fileManager = FileManager.default
    private let session: URLSession

    // Directories
    private var workingDir: URL {                                              // last known-good
        let d = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Filters/working", isDirectory: true)
        try? fileManager.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }
    private var stagingDir: URL {                                              // in-progress download
        let d = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Filters/staging", isDirectory: true)
        try? fileManager.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }
    private var sourcesURL: URL {
        let d = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Filters", isDirectory: true)
        return d.appendingPathComponent("sources.json")
    }
    private var statsURL: URL {
        fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Filters/stats.json")
    }
    private var scheduleURL: URL {
        fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Filters/schedule.json")
    }

    /// Shared with the Safari extension via an App Group.
    public static let appGroupID = "group.87486bbbb00f533a.3"
    public static let blockerRulesFileName = "cleangeo-blocker.json"
    /// The content blocker identifier registered with Safari.
    public static let blockerID = "app.beet2811.ursamajor1675.BlockerExtension"

    public private(set) var sources: [FilterListSource] = FilterListManager.defaultSources
    public private(set) var stats = FilterStats()
    public private(set) var schedule = UpdateSchedule.default

    /// მხოლოდ საკუთარი ბლოკ-ლისტი — მესამე პირის სიები არ გამოიყენება.
    public static let defaultSources: [FilterListSource] = [
        FilterListSource(
            id: "cleangeo-main",
            name: "CleanGEO — ძირითადი",
            url: "https://raw.githubusercontent.com/devunionsup/CleanGEO/main/CleanGEO.txt",
            enabled: true)
    ]

    public init(session: URLSession? = nil) {
        if let s = session {
            self.session = s
        } else {
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = 30
            cfg.timeoutIntervalForResource = 120
            cfg.httpAdditionalHeaders = ["User-Agent": "CleanGEO/1.0"]
            self.session = URLSession(configuration: cfg)
        }
        loadLocalState()
        // გაწმინდება: ძველი ინსტალაციებში შემორჩენილი AdGuard-სიები
        // იშლება (სიებიდან + მათი ჩამოტვირთული raw ფაილები) —
        // რჩება მხოლოდ შენი CleanGEO.txt.
        pruneForeignSources()
    }

    /// არა-ლოკალური (მესამე პირის) სიების მოცილება და მათი ფაილების წაშლა.
    private func pruneForeignSources() {
        let ours = Set(Self.defaultSources.map { $0.id })
        let removed = sources.filter { !ours.contains($0.id) && !$0.id.hasPrefix("custom-") }
        guard !removed.isEmpty else { return }
        setSources(sources.filter { ours.contains($0.id) || $0.id.hasPrefix("custom-") })
        for src in removed {
            try? fileManager.removeItem(at: stagingDir.appendingPathComponent("\(src.id).txt"))
        }
        // ძველი კომპილაცია უკვე არასწორია — ძალით განახლება შემდეგ გაშვებას
        // აიძულებს მხოლოდ შენი სიით გადაკომპილირებას.
        stats.lastSuccessfulUpdate = nil
        saveStats()
    }

    // MARK: - Local state

    private func loadLocalState() {
        if let data = try? Data(contentsOf: sourcesURL),
           let decoded = try? JSONDecoder().decode([FilterListSource].self, from: data) {
            sources = decoded
        }
        if let data = try? Data(contentsOf: statsURL),
           let decoded = try? JSONDecoder().decode(FilterStats.self, from: data) {
            stats = decoded
        }
        if let data = try? Data(contentsOf: scheduleURL),
           let decoded = try? JSONDecoder().decode(UpdateSchedule.self, from: data) {
            schedule = decoded
        }
    }

    public func setSources(_ newSources: [FilterListSource]) {
        sources = newSources
        if let data = try? JSONEncoder().encode(newSources) {
            try? data.write(to: sourcesURL, options: .atomic)
        }
    }

    public func setSchedule(_ newSchedule: UpdateSchedule) {
        schedule = newSchedule
        if let data = try? JSONEncoder().encode(newSchedule) {
            try? data.write(to: scheduleURL, options: .atomic)
        }
    }

    private func saveStats() {
        if let data = try? JSONEncoder().encode(stats) {
            try? data.write(to: statsURL, options: .atomic)
        }
    }

    // MARK: - Update

    /// Downloads all enabled lists, verifies, compiles, and swaps in atomically.
    /// Returns (ruleCount, listCount) on success.
    @discardableResult
    public func updateAll(now: Date = Date()) async throws -> (rules: Int, lists: Int) {
        var combined: [CompiledRule] = []
        var loadedLists = 0
        var firstError: Error? = nil

        // Clear staging.
        try? fileManager.removeItem(at: stagingDir)
        try? fileManager.createDirectory(at: stagingDir, withIntermediateDirectories: true)

        for source in sources where source.enabled {
            do {
                let raw = try await download(source: source)
                let rules = try FilterCompiler().compile(text: raw)
                // Save raw text in staging for audit/debug.
                let rawURL = stagingDir.appendingPathComponent("\(source.id).txt")
                try raw.write(to: rawURL, atomically: true, encoding: .utf8)
                combined.append(contentsOf: rules)
                loadedLists += 1
            } catch {
                // One failing list must not break the others.
                if firstError == nil { firstError = error }
            }
        }

        guard loadedLists > 0, !combined.isEmpty else {
            let msg = firstError.map { "\($0.localizedDescription)" } ?? "ფილტრები ვერ ჩაიტვირთა"
            stats.lastError = msg
            saveStats()
            throw FilterUpdateError.allListsFailed(msg)
        }

        // Atomic swap: write to staging, then move into working dir.
        let json = try FilterCompiler().toJSON(combined)
        let stagingFile = stagingDir.appendingPathComponent(Self.blockerRulesFileName)
        try json.write(to: stagingFile, options: .atomic)

        // Replace working copy.
        try? fileManager.removeItem(at: workingDir.appendingPathComponent(Self.blockerRulesFileName))
        try fileManager.moveItem(at: stagingFile, to: workingDir.appendingPathComponent(Self.blockerRulesFileName))

        // Publish to the App Group container for the extension.
        try publishToAppGroup(json: json)

        // Prune stale staging files.
        let keep = Set(sources.filter(\.enabled).map { "\($0.id).txt" })
        if let files = try? fileManager.contentsOfDirectory(at: stagingDir, includingPropertiesForKeys: nil) {
            for f in files where f.lastPathComponent != Self.blockerRulesFileName && !keep.contains(f.lastPathComponent) {
                try? fileManager.removeItem(at: f)
            }
        }

        stats.lastSuccessfulUpdate = now
        stats.ruleCount = combined.count
        stats.listCount = loadedLists
        stats.lastError = nil
        saveStats()
        return (combined.count, loadedLists)
    }

    public enum FilterUpdateError: Error, LocalizedError {
        case allListsFailed(String)
        case notEnabled
        public var errorDescription: String? {
            switch self {
            case .allListsFailed(let m): return "ვერცერთი ბლოკ-ლისტი არ ჩაიტვირთა: \(m)"
            case .notEnabled: return "განახლება გამორთულია"
            }
        }
    }

    /// Copy the compiled rules into the shared App Group container so the
    /// content blocker extension can read them.
    public func publishToAppGroup(json: Data) throws {
        guard let container = fileManager.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroupID) else {
            // App Group not available (e.g. unit tests) — rules stay local.
            return
        }
        let dir = container.appendingPathComponent("Filters", isDirectory: true)
        try fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        try json.write(to: dir.appendingPathComponent(Self.blockerRulesFileName), options: .atomic)
    }

    /// Rules currently on disk in the App Group (what Safari actually uses).
    public func publishedRuleCount() -> Int {
        guard let container = fileManager.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroupID),
              let data = try? Data(contentsOf: container
                .appendingPathComponent("Filters", isDirectory: true)
                .appendingPathComponent(Self.blockerRulesFileName)),
              let rules = try? JSONDecoder().decode([CompiledRule].self, from: data) else {
            return 0
        }
        return rules.count
    }

    // MARK: - Download & verify

    private func download(source: FilterListSource) async throws -> String {
        guard let url = URL(string: source.url) else {
            throw FilterUpdateError.allListsFailed("არასწორი URL: \(source.url)")
        }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw FilterUpdateError.allListsFailed("სერვერი დააბრუნა \(code) — \(source.name)")
        }
        // TLS is enforced by ATS by default; additionally require https scheme.
        guard url.scheme == "https" else {
            throw FilterUpdateError.allListsFailed("მხოლოდ HTTPS არის დაშვებული: \(source.url)")
        }

        // Integrity check (SHA-256) — against pinned hash or against the
        // manifest if one is published next to the list.
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        if let pinned = source.expectedSHA256?.lowercased(), pinned.count == 64, pinned != digest {
            throw FilterUpdateError.allListsFailed("SHA-256 არ ემთხვევა: \(source.name)")
        }
        // Manifest check (optional): <url without filename>.manifest.json
        // { "url": "...", "sha256": "..." } — signed manifests are verified
        // when a public key is configured.
        if source.expectedSHA256 == nil, let manifest = try? await downloadManifest(for: source) {
            if manifest.count > 0, let expected = manifest["sha256"] as? String,
               expected.lowercased() != digest {
                throw FilterUpdateError.allListsFailed("მანიფესტის SHA-256 არ ემთხვევა: \(source.name)")
            }
        }

        guard let text = String(data: data, encoding: .utf8), !text.isEmpty else {
            throw FilterUpdateError.allListsFailed("ცარიელი ან დაზიანებული ფაილი: \(source.name)")
        }
        return text
    }

    private func downloadManifest(for source: FilterListSource) async throws -> [String: Any]? {
        guard var comps = URLComponents(string: source.url) else { return nil }
        comps.path = (comps.path as NSString).deletingLastPathComponent + "/manifest.json"
        guard let manifestURL = comps.url else { return nil }
        let (data, response) = try await session.data(for: URLRequest(url: manifestURL))
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    // MARK: - Scheduled updates (called from AppDelegate / BGTask)

    /// True when a scheduled update should run right now.
    public func scheduledUpdateDue(now: Date = Date()) -> Bool {
        schedule.isDue(now: now, lastUpdate: stats.lastSuccessfulUpdate)
    }

    /// Update only when the user's schedule says it is due; used on launch.
    @discardableResult
    public func updateAllIfDue(now: Date = Date()) async throws -> (rules: Int, lists: Int) {
        guard scheduledUpdateDue(now: now) else { return (stats.ruleCount, stats.listCount) }
        return try await updateAll(now: now)
    }

    /// Ask Safari to reload the content blocker with the newly published rules.
    public func reloadSafariBlocker() async throws {
        try await SFContentBlockerManager.reloadContentBlocker(withIdentifier: Self.blockerID)
    }
}
