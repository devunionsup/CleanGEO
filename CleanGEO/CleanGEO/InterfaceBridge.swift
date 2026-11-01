import Foundation
import WebKit
import NetworkExtension

/// JS <-> Swift bridge. JS: window.webkit.messageHandlers.bridge.postMessage({id, cmd, args})
/// Swift answers with window.__bridgeReply(id, jsonString). Pushes only when the state signature changes.
@MainActor
final class InterfaceBridge: NSObject, WKScriptMessageHandler {
    weak var web: WKWebView?
    private var lastSignature = ""
    private var timer: Timer?

    override init() {
        super.init()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.pushIfChanged() }
        }
    }

    func userContentController(_ c: WKUserContentController, didReceive m: WKScriptMessage) {
        guard let body = m.body as? [String: Any], let id = body["id"] as? Int,
              let cmd = body["cmd"] as? String else { return }
        let args = body["args"] as? [String: Any] ?? [:]
        Task { reply(id, await handle(cmd, args)) }
    }

    private func handle(_ cmd: String, _ args: [String: Any]) async -> [String: Any] {
        switch cmd {
        case "getState": break
        case "toggleTunnel":
            do { try await TunnelManager.shared.setEnabled(args["on"] as? Bool ?? false) }
            catch { return ["error": "ტუნელის ჩართვა ვერ მოხერხდა: \(error.localizedDescription)"] }
        case "updateFilters": await FilterListManager.shared.update()
        case "addList":
            if let u = args["url"] as? String, u.hasPrefix("https://") {
                FilterListManager.shared.userLists.append(u); await FilterListManager.shared.update()
            } else { return ["error": "მხოლოდ https-სია დაიშვება"] }
        case "removeList":
            if let u = args["url"] as? String { FilterListManager.shared.userLists.removeAll { $0 == u } }
        case "clearStats": DNSStats().save()
        case "probeDoH":
            let ms = await withCheckedContinuation { (k: CheckedContinuation<Int?, Never>) in
                DoHClient.probe(args["url"] as? String ?? DoHClient.defaultChain[0]) { k.resume(returning: $0) }
            }
            return ["latency": ms as Any? ?? NSNull()]
        default: return ["error": "უცნობი ბრძანება"]
        }
        return state()
    }

    func state() -> [String: Any] {
        let s = DNSStats.load()
        let f = FilterListManager.shared
        let days = (0..<7).reversed().map { i -> [String: Any] in
            let k = DNSStats.dayKey(Date().addingTimeInterval(Double(-i) * 86400))
            let d = s.daily[k] ?? DayStat()
            return ["day": k, "total": d.total, "blocked": d.blocked]
        }
        return [
            "tunnel": TunnelManager.shared.statusText,
            "tunnelOn": TunnelManager.shared.status == .connected,
            "total": s.total, "blocked": s.blocked, "ads": s.ads, "trackers": s.trackers,
            "bytes": s.bytes,
            "top": s.topTen.map { ["domain": $0.0, "count": $0.1] },
            "days": days,
            "rules": f.ruleCount,
            "lastUpdate": f.lastUpdate.map { ISO8601DateFormatter().string(from: $0) } as Any? ?? NSNull(),
            "lists": f.userLists,
            "error": f.lastError as Any? ?? NSNull()
        ]
    }

    private func json(_ o: Any) -> String {
        (try? JSONSerialization.data(withJSONObject: o)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    }
    private func reply(_ id: Int, _ o: [String: Any]) {
        web?.evaluateJavaScript("window.__bridgeReply(\(id), \(json(o)))")
    }
    private func pushIfChanged() {
        let j = json(state())
        guard j != lastSignature else { return }
        lastSignature = j
        web?.evaluateJavaScript("window.__push(\(j))")
    }
}
