import Foundation
import NetworkExtension

@MainActor
final class TunnelManager: ObservableObject {
    static let shared = TunnelManager()
    static let providerBundleID = "DEV.GIORGI.DEV.VPN"

    @Published var status: NEVPNStatus = .invalid
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    func load() async {
        let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        manager = all.first
        observe()
    }

    private func observe() {
        guard let m = manager else { return }
        status = m.connection.status
        if let o = observer { NotificationCenter.default.removeObserver(o) }
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: m.connection, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.status = self?.manager?.connection.status ?? .invalid }
        }
    }

    func setEnabled(_ on: Bool) async throws {
        if !on { manager?.connection.stopVPNTunnel(); return }
        do { try await install() }
        catch {                                    // broken profile ("Update Required"): wipe and recreate
            try? await manager?.removeFromPreferences()
            manager = nil
            try await install()
        }
        try manager?.connection.startVPNTunnel()
    }

    private func install() async throws {
        let m = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        proto.serverAddress = "CleanGEO (local)"
        m.protocolConfiguration = proto
        m.localizedDescription = "CleanGEO"
        m.isEnabled = true
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
        manager = m
        observe()
    }

    var statusText: String {
        switch status {
        case .connected: return "ჩართულია"
        case .connecting, .reasserting: return "ერთვება…"
        case .disconnecting: return "ითიშება…"
        default: return "გამორთულია"
        }
    }
}
