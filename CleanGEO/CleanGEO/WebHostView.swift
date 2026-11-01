import SwiftUI
import WebKit

struct WebHostView: UIViewRepresentable {
    func makeCoordinator() -> InterfaceBridge { InterfaceBridge() }

    func makeUIView(context: Context) -> WKWebView {
        let cfg = WKWebViewConfiguration()
        cfg.userContentController.add(context.coordinator, name: "bridge")
        let web = WKWebView(frame: .zero, configuration: cfg)
        web.isOpaque = false
        web.backgroundColor = .clear
        context.coordinator.web = web
        if let dir = Bundle.main.url(forResource: "Web", withExtension: nil) {
            web.loadFileURL(dir.appendingPathComponent("Interface.html"), allowingReadAccessTo: dir)
        }
        return web
    }
    func updateUIView(_ uiView: WKWebView, context: Context) {}
}
