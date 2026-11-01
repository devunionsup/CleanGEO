//
//  TunnelManager.swift
//  CleanGEO
//
//  Manages the local CleanGEO privacy tunnel (NetworkExtension
//  packet-tunnel-provider). The tunnel is LOCAL: encryption (ChaCha20-style
//  sealed boxes) happens entirely on the device. No remote VPN server is
//  contacted. The only egress the tunnel permits is DNS-over-HTTPS to the
//  configured AdGuard endpoints:
//
//    1. https://dns.adguard-dns.com/dns-query        (primary)
//    2. https://family.adguard-dns.com/dns-query     (automatic fallback)
//
//  If the primary does not answer or returns errors, the tunnel switches to
//  the fallback on its own and remembers the working endpoint.
//

import Foundation
import NetworkExtension

public final class TunnelManager: ObservableObject {

    public static let shared = TunnelManager()
    static let tunnelBundleID = "app.beet2811.ursamajor1675.CleanGEOVPN"

    // MARK: - DoH chain (primary → automatic fallback)

    public static let dohPrimary = "https://dns.adguard-dns.com/dns-query"
    public static let dohFallback = "https://family.adguard-dns.com/dns-query"
    public static let doTHostPrimary = "dns.adguard-dns.com"
    public static let doTHostFallback = "family.adguard-dns.com"

    /// The chain handed to the tunnel process. The provider tries the
    /// endpoints in order and uses the first one that answers.
    public static let dohChain = [dohPrimary, dohFallback]

    /// Endpoint the user selected in the UI ("" = automatic).
    @Published public private(set) var activeEndpoint: String = ""

    @Published public private(set) var status: NEVPNStatus = .invalid
    @Published public private(set) var lastError: String?

    private var manager: NETunnelProviderManager?

    private init() {
        reloadStatus()
    }

    // MARK: - Status

    public func reloadStatus() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error {
                    self.lastError = error.localizedDescription
                    return
                }
                let ours = managers?.filter { $0 as? NETunnelProviderManager != nil } ?? []
                if let existing = ours.first {
                    self.manager = existing
                    self.status = existing.connection.status
                    existing.connection.observe(\.status, options: []) { [weak self] conn, _ in
                        DispatchQueue.main.async {
                            self?.status = conn.status
                        }
                    }
                } else {
                    self.manager = nil
                    self.status = .invalid
                }
            }
        }
    }

    // MARK: - Enable

    /// Build (once) and start the local filtering tunnel. iOS shows the
    /// system "VPN" permission prompt the first time.
    /// თუ ძველი პროფილი „Update Required"-ია (აპი გადაყენებულია), ვშლით და
    /// ნულიდან ვქმნით — ავტო-აღდგენა.
    public func enable(dnsServers: [String] = ["10.111.222.1"],
                       dohChainOverride: [String]? = nil) async throws {
        do {
            try await enableInternal(dnsServers: dnsServers, dohChainOverride: dohChainOverride)
        } catch {
            await removeFromDevice()
            try await enableInternal(dnsServers: dnsServers, dohChainOverride: dohChainOverride)
        }
    }

    private func enableInternal(dnsServers: [String], dohChainOverride: [String]?) async throws {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.tunnelBundleID
        // Local privacy tunnel: the label shown in iOS Settings.
        proto.serverAddress = "CleanGEO (ლოკალური)"
        // ჯაჭვი: მომხმარებლის DoH (თუ არის) → AdGuard primary → fallback.
        let chain = (dohChainOverride?.isEmpty == false) ? dohChainOverride! : Self.dohChain
        // Provider-side configuration, read in the tunnel process.
        proto.providerConfiguration = [
            "mode": "local-doh",
            "dohChain": chain.joined(separator: " "),
            "dotHosts": [Self.doTHostPrimary, Self.doTHostFallback].joined(separator: " "),
            "dns": dnsServers.joined(separator: ","),
            "mtu": 1_420
        ]
        proto.disconnectOnSleep = false

        let mgr = manager ?? NETunnelProviderManager()
        mgr.protocolConfiguration = proto
        mgr.isEnabled = true
        mgr.localizedDescription = "CleanGEO VPN"
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        try mgr.connection.startVPNTunnel()
        manager = mgr
        reloadStatus()
    }

    public func disable() async {
        guard let mgr = manager else { return }
        try? await mgr.connection.stopVPNTunnel()
        reloadStatus()
    }

    /// Full removal of EVERY VPN profile this app created (წმენდს დუბლიკატებსაც).
    public func removeFromDevice() async {
        let all: [NETunnelProviderManager] = await withCheckedContinuation { cont in
            NETunnelProviderManager.loadAllFromPreferences { managers, _ in
                cont.resume(returning: (managers as? [NETunnelProviderManager]) ?? [])
            }
        }
        for m in all { try? await m.removeFromPreferences() }
        manager = nil
        status = .invalid
    }

    public var statusText: String {
        switch status {
        case .connected:          return "დაკავშირებულია"
        case .connecting:         return "მიმდინარეობს დაკავშირება…"
        case .disconnected:       return "გათიშულია"
        case .disconnecting:      return "ითიშება…"
        case .reasserting:        return "აღდგენა…"
        case .invalid:            return "არ არის დაყენებული"
        default:                  return "უცნობი მდგომარეობა"
        }
    }
}
