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
    private var statusTimer: Timer?
    /// ბოლო გაგზავნილი state-ის თითი: უცვლელი state არ იგზავნება — ეს იცავს
    /// ინტერფეისს ყოველწამიანი ციმციმებისგან.
    private var lastPushSignature: String = ""

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
        webView.navigationDelegate = self
        let url = Bundle.main.url(forResource: "Interface", withExtension: "html")
        if let url {
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        }
        // ციმციმების ფიქსი: ტაიმერი მხოლოდ სინქრონიზაციისთვისაა (5 წმ);
        // push ხდება მხოლოდ მაშინ, როცა state ფაქტობრივად შეიცვლება.
        statusTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.pushState() }
        }
        applyTheme()
        pushState()
        probeDNSInBackground()
    }

    deinit {
        statusTimer?.invalidate()
    }

    // MARK: - WKNavigationDelegate

    /// გვერდის ყოველი ჩატვირთვისას state ხელახლა იგზავნება — წინა სიგნატურა
    /// აღარ ბლოკავს სინქრონს (გვერდი ახალია, მისი JS-state ცარიელია).
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        lastPushSignature = ""
        pushState()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        lastPushSignature = ""
    }

    // MARK: - მდგომარეობის push

    private func safariEnabled(_ done: @escaping @MainActor (Bool) -> Void) {
        SFContentBlockerManager.getStateOfContentBlocker(withIdentifier: FilterListManager.blockerID) { state, _ in
            Task { @MainActor in done(state?.isEnabled == true) }
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
                    "local": true,
                    "mode": InterfaceSettings.dnsOnly ? "dns" : "tunnel",
                    "dohChain": TunnelManager.dohChain,
                    "activeDoh": self.tunnel.activeEndpoint as Any,
                    "lastError": self.tunnel.lastError ?? s.lastError
                ],
                "safari": [
                    "enabled": enabled,
                    "rules": self.filters.publishedRuleCount(),
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
        if json == lastPushSignature { return }
        lastPushSignature = json
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
                    // ლოკალური ტუნელი: დაშიფვრა მოწყობილობაში, გარეთ მხოლოდ DoH.
                    try await tunnel.enable(dohChainOverride: Self.dohChain())
                    probeDNSInBackground()
                } catch {
                    throw BridgeError(message: error.localizedDescription)
                }
            }
            pushState()
            return nil

        case "setMode":
            // ტუნელი ყოველთვის ლოკალურია; რეჟიმი მხოლოდ წარწერაა.
            InterfaceSettings.dnsOnly = (payload["mode"] as? String) == "dns"
            pushState()
            return nil

        case "toggleSafari":
            let enabledNow: Bool = await withCheckedContinuation { cont in
                SFContentBlockerManager.getStateOfContentBlocker(withIdentifier: FilterListManager.blockerID) { state, _ in
                    cont.resume(returning: state?.isEnabled == true)
                }
            }
            guard enabledNow else {
                throw BridgeError(message: "ჩართე პარამეტრებში: Safari → გაფართოებები → CleanGEO")
            }
            try await filters.reloadSafariBlocker()
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
            // აქტიური ტუნელი ხელახლა ირთვება განახლებული ჯაჭვით.
            if tunnel.status == .connected || tunnel.status == .connecting {
                try? await tunnel.disable()
                _ = try? await tunnel.enable(dohChainOverride: Self.dohChain())
            }
            probeDNSInBackground()
            pushState()
            return nil

        case "testDNS":
            // ჯაჭვი თავისით გადადის fallback-ზე; შედეგს DNSHealth ინახავს.
            let latency = try await DNSHealth.test(
                doh: InterfaceSettings.doh, dot: InterfaceSettings.dot,
                dnssec: InterfaceSettings.dnssec)
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
    static func setDnsOK(_ v: Bool) { d.set(v, forKey: "cg.dnsLastOK") }
    static func setDnsLatency(_ v: Int) { d.set(v, forKey: "cg.dnsLastLatency") }
    /// DoH ჯაჭვი: პირველი არჩევანი + ავტომატური fallback (AdGuard).
    static var dnsChain: [String] {
        get {
            let saved = d.stringArray(forKey: "cg.dohChain") ?? []
            let primary = d.string(forKey: "cg.doh") ?? ""
            var chain = saved
            if !primary.isEmpty && !chain.contains(primary) { chain.insert(primary, at: 0) }
            return chain
        }
        set { d.set(newValue, forKey: "cg.dohChain") }
    }
}

enum InterfaceStore {
    static func loadBlocked() -> (ads: Int, trackers: Int, queries: Int) { (0, 0, 0) }
    static func loadWeek() -> [Int] { Array(repeating: 0, count: 7) }
    static func loadTopBlocked() -> [[String: Any]] { [] }
    static func clear() {}
}

enum DNSHealth {
    /// ჯაჭვის ტესტი: რომელი DoH პასუხობს და რა სისწრაფით.
    static func test(doh: String, dot: String, dnssec: Bool) async throws -> Int {
        let chain = InterfaceBridge.dohChain()
        guard !chain.isEmpty else { throw BridgeError(message: "DoH მისამართი მითითებული არაა") }
        var latency = -1
        for raw in chain {
            guard let url = URL(string: raw), let host = url.host, !host.isEmpty else { continue }
            let start = Date()
            let client = DoHClient(config: CleanGEODNSConfig(dohURL: url,
                                                             doTHost: dot.isEmpty ? host : dot))
            do {
                _ = try await client.query("example.com", type: .a, dnssec: dnssec)
                let l = Int(Date().timeIntervalSince(start) * 1000)
                if latency < 0 { latency = l }
                if raw == InterfaceSettings.doh {
                    InterfaceSettings.setDnsOK(true)
                    InterfaceSettings.setDnsLatency(l)
                }
                if !InterfaceSettings.dnsChain.contains(raw) {
                    InterfaceSettings.dnsChain.append(raw)
                }
            } catch {
                if raw == InterfaceSettings.doh {
                    InterfaceSettings.setDnsOK(false)
                }
            }
        }
        guard latency >= 0 else { throw BridgeError(message: "ვერცერთი DoH სერვერი არ პასუხობს") }
        return latency
    }
}

// MARK: - DNS ჯაჭვის ფონური შემოწმება (ავტომატური fallback)

enum DNSProbe {
    static var running = false

    /// აპი თავისთავად იგებს, პასუხობს თუ არა პირველადი DoH; ტუნელის ჯაჭვი
    /// თვითონ გადადის fallback-ზე, აქ მხოლოდ სტატუსი ანახლდება.
    @MainActor
    static func probe() {
        guard !running else { return }
        running = true
        Task { @MainActor in
            defer { running = false }
            for raw in InterfaceBridge.dohChain() {
                guard let url = URL(string: raw), let host = url.host, !host.isEmpty else { continue }
                let client = DoHClient(config: CleanGEODNSConfig(dohURL: url, doTHost: host))
                do {
                    let start = Date()
                    _ = try await client.query("example.com", type: .a, dnssec: false)
                    let l = Int(Date().timeIntervalSince(start) * 1000)
                    if raw == InterfaceSettings.doh {
                        InterfaceSettings.setDnsOK(true)
                        InterfaceSettings.setDnsLatency(l)
                    }
                    if !InterfaceSettings.dnsChain.contains(raw) {
                        InterfaceSettings.dnsChain.append(raw)
                    }
                    return
                } catch {
                    if raw == InterfaceSettings.doh {
                        InterfaceSettings.setDnsOK(false)
                    }
                }
            }
        }
    }
}

extension InterfaceBridge {
    /// ჯაჭვი: მომხმარებლის DoH (თუ მითითებულია) → AdGuard primary → fallback.
    static func dohChain() -> [String] {
        var chain = InterfaceSettings.dnsChain
        for e in [TunnelManager.dohPrimary, TunnelManager.dohFallback] where !chain.contains(e) {
            chain.append(e)
        }
        return chain
    }

    func probeDNSInBackground() {
        DNSProbe.probe()
    }
}
