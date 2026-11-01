import Foundation
import CryptoKit
import SafariServices
import BackgroundTasks

@MainActor
final class FilterListManager: ObservableObject {
    static let shared = FilterListManager()
    static let refreshTaskID = "DEV.GIORGI.DEV.refresh"
    static let blockerBundleID = "DEV.GIORGI.DEV.BlockerExtension"

    @Published var ruleCount = 0
    @Published var lastUpdate: Date?
    @Published var lastError: String?

    var userLists: [String] {
        get { AppGroup.defaults.stringArray(forKey: "userLists") ?? [] }
        set { AppGroup.defaults.set(newValue, forKey: "userLists") }
    }

    /// Download (https only), compile, publish to the App Group, reload Safari extension.
    func update() async {
        do {
            var sources: [String] = []
            if let u = Bundle.main.url(forResource: "CleanGEO", withExtension: "txt"),
               let s = try? String(contentsOf: u, encoding: .utf8) { sources.append(s) }
            for urlStr in userLists {
                guard let url = URL(string: urlStr), url.scheme == "https" else { continue }
                let (data, resp) = try await URLSession.shared.data(from: url)
                guard (resp as? HTTPURLResponse)?.statusCode == 200,
                      let s = String(data: data, encoding: .utf8) else { continue }
                _ = SHA256.hash(data: data)     // TODO: compare with pinned hash when provided
                sources.append(s)
            }
            let out = FilterCompiler.compile(sources.joined(separator: "\n"))
            try out.json.write(to: AppGroup.blockerJSON, options: .atomic)   // old list kept on failure above
            try out.domainList.write(to: AppGroup.domainList, atomically: true, encoding: .utf8)
            ruleCount = out.ruleCount
            lastUpdate = Date(); lastError = nil
            AppGroup.defaults.set(Date(), forKey: "lastUpdate")
            try await SFContentBlockerManager.reloadContentBlocker(withIdentifier: Self.blockerBundleID)
        } catch {
            lastError = error.localizedDescription
        }
    }

    func updateIfStale(hours: Double = 6) async {
        let last = AppGroup.defaults.object(forKey: "lastUpdate") as? Date ?? .distantPast
        if Date().timeIntervalSince(last) > hours * 3600 { await update() }
    }

    // MARK: background refresh
    nonisolated static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: refreshTaskID, using: nil) { task in
            schedule()
            let work = Task { await FilterListManager.shared.update(); task.setTaskCompleted(success: true) }
            task.expirationHandler = { work.cancel() }
        }
    }
    nonisolated static func schedule() {
        let r = BGAppRefreshTaskRequest(identifier: refreshTaskID)
        r.earliestBeginDate = Date(timeIntervalSinceNow: 6 * 3600)
        try? BGTaskScheduler.shared.submit(r)
    }
}
