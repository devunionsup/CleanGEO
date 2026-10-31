//
//  TunnelManager.swift
//  CleanGEO
//
//  Manages the optional CleanGEO privacy tunnel (NetworkExtension
//  packet-tunnel-provider). Creates the system VPN configuration on demand;
//  DNS is pointed at the CleanGEO resolver so the ISP cannot see or rewrite
//  DNS traffic, and traffic flows through the tunnel ( WireGuard-style
//  encrypted hop to the user's own CleanGEO node).
//

import Foundation
import NetworkExtension

public final class TunnelManager: ObservableObject {

    public static let shared = TunnelManager()
    static let tunnelBundleID = "ge.cleangeo.app.tunnel"

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
                    existing.connection.observe(\.status) { [weak self] conn in
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

    /// Build (once) and start the tunnel. Requires the NetworkExtension
    /// entitlement; iOS shows the system "VPN" permission prompt the first
    /// time, so this must run in the foreground of the app.
    public func enable(nodeAddress: String,
                       nodePublicKeyBase64: String,
                       allowedIPs: [String] = ["0.0.0.0/0", "::/0"],
                       dnsServers: [String] = ["10.111.222.1"]) async throws {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.tunnelBundleID
        proto.serverAddress = nodeAddress
        // Provider-side configuration, read in the tunnel process.
        proto.providerConfiguration = [
            "endpoint": nodeAddress,
            "peerPublicKey": nodePublicKeyBase64,
            "allowedIPs": allowedIPs.joined(separator: ","),
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

    public func disable() async throws {
        guard let mgr = manager else { return }
        try await mgr.connection.stopVPNTunnel()
        reloadStatus()
    }

    /// Full removal of the VPN profile from the system.
    public func removeFromDevice() async throws {
        guard let mgr = manager else { return }
        mgr.removeFromPreferences()
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
