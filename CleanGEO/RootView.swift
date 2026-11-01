//
//  RootView.swift
//  CleanGEO
//
//  v5 ინტერფეისი: მთელი UI App/Interface.html-შია (WebKit, ლიკვიდ-მინის
//  დიზაინი). Swift-ბრიჯი — App/InterfaceBridge.swift.
//
//  ძველი SwiftUI ეკრანები (HomeScreen/StatsScreen/ProtectionScreen/FiltersScreen/
//  DNSScreen/SafariScreen/PrivacyScreen/AboutScreen/MoreScreen) მოცილებულია —
//  მათში ჩაშენებული ტესტო მონაცემები იყო და დუბლირებას ქმნიდა. ინტერფეისს
//  ახლა ერთი წყარო აქვს: WebKit-გვერდი + ბრიჯი.
//
//  ეკრანები → სერვისები:
//   • მთავარი/VPN → TunnelManager (ლოკალური ტუნელი, AdGuard DoH-ჯაჭვი)
//   • ფილტრები   → FilterListManager (App Group → Safari blocker)
//   • DNS        → DoH ჯაჭვი: dns.adguard-dns.com → family.adguard-dns.com
//   • თემა       → Theme / ThemeBridge
//

import SwiftUI
import WebKit

// MARK: - UI მდგომარეობა (თემა/ნავიგაცია)

enum CGUITheme: String {
    case auto, light, dark
}

// MARK: - WebView კონტეინერი (App/Interface.html)

struct WebViewHost: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> UIViewController {
        let vc = UIViewController()
        vc.view.backgroundColor = .clear
        let web = InterfaceBridge.makeWebView()
        context.coordinator.bridge = InterfaceBridge()
        web.translatesAutoresizingMaskIntoConstraints = false
        vc.view.addSubview(web)
        NSLayoutConstraint.activate([
            web.topAnchor.constraint(equalTo: vc.view.topAnchor),
            web.bottomAnchor.constraint(equalTo: vc.view.bottomAnchor),
            web.leadingAnchor.constraint(equalTo: vc.view.leadingAnchor),
            web.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor)
        ])
        context.coordinator.bridge?.attach(to: web)
        return vc
    }

    func updateUIViewController(_ vc: UIViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator {
        var bridge: InterfaceBridge?
    }
}

enum InterfaceStartup {
    /// სპეციფიკაცია: ფილტრების განახლების შემოწმება გაშვებისას.
    static func checkOnLaunch() async {
        if FilterListManager.shared.scheduledUpdateDue() {
            _ = try? await FilterListManager.shared.updateAll()
        }
    }

    /// ფონიდან დაბრუნებისასაც ხდება შემოწმება (BGTask-ის გარდა).
    static func checkOnForeground() {
        Task.detached(priority: .utility) {
            if FilterListManager.shared.scheduledUpdateDue() {
                _ = try? await FilterListManager.shared.updateAll()
            }
            try? await FilterListManager.shared.reloadSafariBlocker()
        }
    }
}

@MainActor
final class UIState: ObservableObject {
    @Published var tab = "home"
    @Published var stack: [String] = []
    @Published var theme: CGUITheme = {
        if let raw = UserDefaults.standard.string(forKey: "cg.theme"),
           let t = CGUITheme(rawValue: raw) { return t }
        return .auto
    }()
    static weak var shared: UIState?

    var current: String { stack.last ?? tab }
    var isSubpage: Bool { !stack.isEmpty }

    init() {
        UIState.shared = self
    }

    func setTheme(_ t: CGUITheme) {
        theme = t
        UserDefaults.standard.set(t.rawValue, forKey: "cg.theme")
    }
}

struct RootView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var ui: UIState
    @Environment(\.scenePhase) var scenePhase
    @Environment(\.colorScheme) private var systemScheme

    var body: some View {
        let effective: ColorScheme? = {
            switch ui.theme {
            case .auto: return nil
            case .light: return .light
            case .dark: return .dark
            }
        }()
        return WebViewHost()
            .ignoresSafeArea()
            .environment(\.colorScheme, effective ?? systemScheme)
            .preferredColorScheme(effective)
            .onChange(of: scenePhase) { phase in
                if phase == .active { InterfaceStartup.checkOnForeground() }
            }
            .task { await InterfaceStartup.checkOnLaunch() }
    }
}
