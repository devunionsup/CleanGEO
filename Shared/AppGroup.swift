import Foundation

/// App Group — ერთადერთი საერთო სივრცე აპს, Safari-ბლოკერს და VPN-გაფართოებას შორის.
enum AppGroup {
    static let id = "group.87486bbbb00f533a.3"

    static var container: URL {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id)
            ?? FileManager.default.temporaryDirectory
    }
    static var filtersDir: URL {
        let u = container.appendingPathComponent("Filters", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
    static var blockerJSON: URL { filtersDir.appendingPathComponent("cleangeo-blocker.json") }
    static var domainList: URL { filtersDir.appendingPathComponent("dns-blocklist.txt") }
    static var statsFile: URL { filtersDir.appendingPathComponent("dns-stats.json") }
    static var defaults: UserDefaults { UserDefaults(suiteName: id) ?? .standard }
}
