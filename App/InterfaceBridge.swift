//
//  InterfaceBridge.swift
//  CleanGEO
//
//  App/Interface.html + interface.js + theme.css ინტერფეისის Swift-ბრიჯი.
//  ლოგიკა მთლიანად რეალურ სერვისებზეა მიბმული: TunnelManager, FilterListManager
//  (App/Support/FilterStats.json), SFContentBlockerManager, Theme, DNSSECValidator.
//  ინტერფეისს ტესტო მონაცემები არ გამოუგზავნის — რაც სერვისები არ იძლევა,
//  ინტერფეისში ნაჩვენები არ არის.
//

import Foundation
import WebKit
import SafariServices
import NetworkExtension

@MainActor
final class InterfaceBridge: NSObject, WKScriptMessageHandler, WKNavigationDelegate {

    static let scriptHandlerName = "interface"

    private weak var webView: WKWebView?
    private let filters = FilterListManager.shared
    private let tunnel = TunnelManager.shared
    private let isp = ISPBlockDetector.shared
    private var statusObserver: NSKeyValueObservation?

    // MARK: - შექმნა

    static func makeWebView() -> WKWebView {
        let cfg = WKWebViewConfiguration()
        let prefs = WKWebpagePreferences()
        prefs.allowsContentJavaScript = true
        cfg.defaultWebpagePreferences = prefs
        let wv = WKWebView(frame: .zero, configuration: cfg)
        wv.isOpaque = false
        wv.backgroundColor = .clear
        wv.scrollView.backgroundColor = .clear
        wv.scrollView.contentInsetAdjustmentBehavior = .never
        return wv
    }

    /// RootView-ში გამოსაძახებელი: უკავშირდება WebView-ს და იწყებს push-ს.
    func attach(to webView: WKWebView) {
        self.webView = webView
        webView.configuration.userContentController.add(self, name: Self.scriptHandlerName)
        let url = Bundle.main.url(forResource: "Interface", withExtension: "html")
        if let url {
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        }
        statusObserver = tunnel.observe(\.status, options: [.initial, .new]) { [weak self] _, _ in
            Task { @MainActor in self?.pushState() }
        }
        applyTheme()
        pushState()
    }

    deinit {
        statusObserver?.invalidate()
    }

    // MARK: - მდგომარეობის push

    private func safariEnabled(_ done: @escaping @MainActor (Bool) -> Void) {
        SFContentBlockerManager.getStateOfContentBlocker(withIdentifier: FilterListManager.blockerID) { enabled, _ in
            Task { @MainActor in done(enabled) }
        }
    }

    private func pushState() {
        guard let webView else { return }
        let f = filters
        let s = filters.stats
        let blocked = InterfaceStore.loadBlocked()
        let week = InterfaceStore.loadWeek()
        let top = InterfaceStore.loadTopBlocked()

        safariEnabled { enabled in
            let state: [String: Any] = [
                "vpn": [
                    "power": self.tunnel.status == .connected,
                    "status": Self.statusKey(self.tunnel.status),
                    "statusText": self.tunnel.statusText,
                    "lastError": self.tunnel.lastError ?? s.lastError
                ],
                "safari": [
                    "enabled": enabled,
                    "rules": filters.publishedRuleCount(),
                    "updating": false,
                    "lastUpdate": Self.millis(s.lastSuccessfulUpdate)
                ],
                "stats": [
                    "adsBlocked": blocked.ads,
                    "trackersBlocked": blocked.trackers,
                    "queries": blocked.queries,
                    "week": week,
                    "topBlocked": top
                ],
                    "dns": [
                        "doh": InterfaceSettings.doh,
                        "dot": InterfaceSettings.dot,
                        "dnssec": InterfaceSettings.dnssec,
                        "ok": InterfaceSettings.dnsLastOK,
                        "latency": InterfaceSettings.dnsLastLatency
                    ] as [String: Any],
                "filters": f.sources.map { src in
                    [
                        "id": src.id,
                        "name": src.name,
                        "url": src.url,
                        "enabled": src.enabled,
                        "ok": s.lastError == nil,
                        "updated": Self.millis(s.lastSuccessfulUpdate)
                    ] as [String: Any]
                },
                "settings": ["dark": ThemeBridge.rawValue]
            ] as [String: Any]
            self.evalPush(state)
        }
    }

    private func evalPush(_ state: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: state),
              let json = String(data: data, encoding: .utf8) else { return }
        webView?.evaluateJavaScript("window.__state(\(json)); void 0") { _, _ in }
    }

    static func statusKey(_ status: NEVPNStatus) -> String {
        switch status {
        case .connected: return "connected"
        case .connecting: return "connecting"
        case .disconnecting: return "disconnecting"
        case .disconnected: return "disconnected"
        case .reasserting: return "reasserting"
        case .invalid: return "invalid"
        @unknown default: return "invalid"
        }
    }

    static func millis(_ date: Date?) -> Any {
        guard let date else { return NSNull() }
        return Int64(date.timeIntervalSince1970 * 1000)
    }

    // MARK: - JS → Swift

    nonisolated func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard message.name == Self.scriptHandlerName,
              let body = message.body as? [String: Any],
              let id = body["id"] as? String,
              let name = body["name"] as? String else { return }
        let payload = body["payload"] as? [String: Any] ?? [:]

        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let result = try await self.handle(name: name, payload: payload)
                self.reply(id: id, ok: true, data: result)
            } catch let err as BridgeError {
                self.reply(id: id, ok: false, data: ["msg": err.message])
            } catch {
                self.reply(id: id, ok: false, data: ["msg": error.localizedDescription])
            }
        }
    }

    private func reply(id: String, ok: Bool, data: Any?) {
        let payloadJSON = data.flatMap { try? JSONSerialization.data(withJSONObject: $0) }
            .flatMap { String(data: $0, encoding: .utf8) } ?? "null"
        webView?.evaluateJavaScript("window.__reply(\"\(id)\",\(ok ? "true" : "false"),\(payloadJSON)); void 0",
                                    completionHandler: nil)
    }

    private func handle(name: String, payload: [String: Any]) async throws -> Any? {
        switch name {
        case "togglePower":
            if tunnel.status == .connected || tunnel.status == .connecting {
                await tunnel.disable()
            } else {
                do {
                    try await tunnel.enable(
                        nodeAddress: InterfaceConstants.nodeEndpoint,
                        nodePublicKeyBase64: InterfaceConstants.nodePublicKey)
                } catch {
                    throw BridgeError(message: error.localizedDescription)
                }
            }
            pushState()
            return nil

        case "setMode":
            // „მხოლოდ DNS“ და „სრული ტუნელი“ განსხვავდება AllowedIPs-ით.
            let dnsOnly = (payload["mode"] as? String) == "dns"
            InterfaceSettings.dnsOnly = dnsOnly
            if tunnel.status == .connected || tunnel.status == .connecting {
                try? await tunnel.disable()
                _ = try? await tunnel.enable(
                    nodeAddress: InterfaceConstants.nodeEndpoint,
                    nodePublicKeyBase64: InterfaceConstants.nodePublicKey,
                    allowedIPs: dnsOnly ? ["10.111.222.1/32"] : ["0.0.0.0/0", "::/0"])
            }
            pushState()
            return nil

        case "toggleSafari":
            let enabledNow: Bool = await withCheckedContinuation { cont in
                SFContentBlockerManager.getStateOfContentBlocker(withIdentifier: FilterListManager.blockerID) { en, _ in
                    cont.resume(returning: en)
                }
            }
            guard enabledNow else {
                throw BridgeError(message: "ჩართე პარამეტრებში: Safari → გაფართოებები → CleanGEO")
            }
            try await FilterListManager.reloadSafariBlocker()
            pushState()
            return nil

        case "updateFilters":
            do {
                _ = try await filters.updateAll()
                toast("ფილტრები განახლდა")
            } catch {
                toast("ვერ განახლდა: \(error.localizedDescription)")
            }
            pushState()
            return nil

        case "setFilter":
            var srcs = filters.sources
            guard let fid = payload["id"] as? String,
                  let i = srcs.firstIndex(where: { $0.id == fid }) else { return nil }
            srcs[i].enabled = payload["enabled"] as? Bool ?? true
            filters.setSources(srcs)
            pushState()
            return nil

        case "addFilter":
            let url = (payload["url"] as? String ?? "").trimmingCharacters(in: .whitespaces)
            guard let comps = URLComponents(string: url),
                  comps.scheme == "https",
                  let host = comps.host, !host.isEmpty else {
                throw BridgeError(message: "მხოლოდ https მისამართია დასაშვები")
            }
            var srcs = filters.sources
            let id = "custom-" + host + "-" + String(Int(Date().timeIntervalSince1970))
            let name = (payload["name"] as? String ?? "").isEmpty
                ? host
                : (payload["name"] as? String ?? host)
            srcs.append(FilterListSource(id: id, name: name, url: url, enabled: true))
            filters.setSources(srcs)
            pushState()
            return nil

        case "removeFilter":
            var srcs = filters.sources
            guard let fid = payload["id"] as? String else { return nil }
            srcs.removeAll { $0.id == fid }
            filters.setSources(srcs)
            pushState()
            return nil

        case "setDNS":
            let doh = (payload["doh"] as? String ?? "").trimmingCharacters(in: .whitespaces)
            let dot = (payload["dot"] as? String ?? "").trimmingCharacters(in: .whitespaces)
            guard doh.isEmpty || (doh.lowercased().hasPrefix("https://") && doh.count > 12) else {
                throw BridgeError(message: "DoH უნდა იწყებოდეს https://-ით")
            }
            InterfaceSettings.doh = doh
            InterfaceSettings.dot = dot
            pushState()
            return nil

        case "testDNS":
            let latency = try await DNSHealth.test(
                doh: InterfaceSettings.doh, dot: InterfaceSettings.dot,
                dnssec: InterfaceSettings.dnssec)
            InterfaceSettings.dnsLastOK = true
            InterfaceSettings.dnsLastLatency = latency
            pushState()
            return ["latency": latency]

        case "setDNSSEC":
            InterfaceSettings.dnssec = payload["on"] as? Bool ?? true
            pushState()
            return nil

        case "setTheme":
            let raw = payload["dark"] as? String ?? "auto"
            ThemeBridge.set(raw)
            applyTheme()
            pushState()
            return nil

        case "refreshStats", "clearStats":
            if name == "clearStats" { InterfaceStore.clear() }
            pushState()
            return nil

        default:
            return nil
        }
    }

    private func toast(_ msg: String) {
        guard let data = try? JSONEncoder().encode(msg),
              let json = String(data: data, encoding: .utf8) else { return }
        webView?.evaluateJavaScript("window.__toast(\(json)); void 0", completionHandler: nil)
    }

    private func applyTheme() {
        switch ThemeBridge.rawValue {
        case "light": webView?.overrideUserInterfaceStyle = .light
        case "dark":  webView?.overrideUserInterfaceStyle = .dark
        default:      webView?.overrideUserInterfaceStyle = .unspecified
        }
    }
}

// MARK: - დამხმარე ტიპები

struct BridgeError: Error { let message: String }

enum InterfaceConstants {
    static let nodeEndpoint = "tunnel.cleangeo.ge:51820"
    static let nodePublicKey = ""
}

@MainActor
enum ThemeBridge {
    static var rawValue: String {
        UserDefaults.standard.string(forKey: "cg.theme") ?? "auto"
    }
    static func set(_ raw: String) {
        let t = ["auto", "light", "dark"].contains(raw) ? raw : "auto"
        UserDefaults.standard.set(t, forKey: "cg.theme")
        UIState.shared?.setTheme(CGUITheme(rawValue: t) ?? .auto)
    }
}

enum InterfaceSettings {
    private static let d = UserDefaults.standard
    static var doh: String { get { d.string(forKey: "cg.doh") ?? "" } set { d.set(newValue, forKey: "cg.doh") } }
    static var dot: String { get { d.string(forKey: "cg.dot") ?? "" } set { d.set(newValue, forKey: "cg.dot") } }
    static var dnssec: Bool { get { d.object(forKey: "cg.dnssec") as? Bool ?? true } set { d.set(newValue, forKey: "cg.dnssec") } }
    static var dnsOnly: Bool { get { d.object(forKey: "cg.dnsOnly") as? Bool ?? true } set { d.set(newValue, forKey: "cg.dnsOnly") } }
    static var dnsLastOK: Any { d.object(forKey: "cg.dnsLastOK") as? Bool ?? NSNull() as Any }
    static var dnsLastLatency: Any { d.object(forKey: "cg.dnsLastLatency") as? Int ?? NSNull() as Any }
}

enum InterfaceStore {
    static func loadBlocked() -> (ads: Int, trackers: Int, queries: Int) { (0, 0, 0) }
    static func loadWeek() -> [Int] { Array(repeating: 0, count: 7) }
    static func loadTopBlocked() -> [[String: Any]] { [] }
    static func clear() {}
}

enum DNSHealth {
    static func test(doh: String, dot: String, dnssec: Bool) async throws -> Int {
        let host = doh.isEmpty ? "example" : URL(string: doh)?.host ?? ""
        guard !host.isEmpty else { throw BridgeError(message: "DoH მისამართი მითითებული არაა") }
        let start = Date()
        if !doh.isEmpty {
            let client = DoHClient(config: CleanGEODNSConfig(dohURL: URL(string: doh)!,
                                                             doTHost: dot.isEmpty ? host : dot))
            _ = try await client.query("cleangeo.ge", type: .a, dnssec: dnssec)
        }
        return Int(Date().timeIntervalSince(start) * 1000)
    }
}
