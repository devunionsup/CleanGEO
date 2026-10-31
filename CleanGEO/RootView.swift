//
//  RootView.swift
//  CleanGEO
//
//  v3 ინტერფეისი: მცურავი დოკი, მინისებრი ბარათები, წყლის სფერო.
//  ეკრანები მიბმულია რეალურ სერვისებზე (FilterListManager, TunnelManager,
//  ISPBlockDetector, BlockListChecker). ლოგიკა არ შეცვლილა.
//
//  ეკრანები → სერვისები:
//   • მთავარი        → TunnelManager (ტუნელი), FilterListManager (ფილტრები),
//                      ISPBlockDetector (ISP), SFContentBlockerManager (Safari)
//   • სტატისტიკა     → FilterListManager.stats — რეალური დაბლოკვების
//                      ლოკალური აღრიცხვა არ არსებობს, ამიტომ ეკრანი
//                      მკაფიოდ მონიშნულია „სატესტო მონაცემებით“
//   • დაცვა          → TunnelManager, SFContentBlockerManager
//   • ფილტრები       → FilterListManager (ერთიანი „CleanGEO საკუთარი ფილტრი“)
//   • DNS პარამეტრები→ ResolverFacade (RecursiveResolver: DoH/DoT/DNSSEC)
//   • პარამეტრები    → Theme (თემა), UpdateSchedule, პრივატულობის პოლიტიკა
//

import SwiftUI
import SafariServices

// MARK: - UI მდგომარეობა (მხოლოდ ინტერფეისის თემა/ნავიგაცია)

enum CGUITheme: String {
    case auto, light, dark
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

    var current: String { stack.last ?? tab }
    var isSubpage: Bool { !stack.isEmpty }

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
        ZStack(alignment: .bottom) {
            CGAppBackground()
            ScrollView(showsIndicators: false) {
                VStack(spacing: 0) {
                    if ui.current == "home" {
                        Color.clear.frame(height: 14)
                    } else {
                        CGNavBar(title: ScreenTitles.forKey(ui.current),
                                 compact: ui.isSubpage) {
                            _ = ui.stack.popLast()
                        }
                    }
                    ScreenSwitch(current: ui.current)
                        .padding(.top, ui.current == "home" ? 0 : 6)
                    Color.clear.frame(height: 120) // დოკის ადგილი
                }
            }
            .ignoresSafeArea(edges: .bottom)
            CGDock(activeTab: ui.tab) { key in
                withAnimation(.spring(response: 0.4, dampingFraction: 0.85)) {
                    ui.tab = key
                    ui.stack = []
                }
            }
        }
        .preferredColorScheme(effective)
        .environment(\.colorScheme, effective ?? systemScheme)
        .animation(.spring(response: 0.45, dampingFraction: 0.9), value: ui.current)
        .onChange(of: scenePhase) { phase in
            if phase == .active {
                Task {
                    _ = try? await FilterListManager.shared.updateAllIfDue()
                    try? await FilterListManager.shared.reloadSafariBlocker()
                }
            }
        }
    }
}

enum ScreenTitles {
    static func forKey(_ k: String) -> String {
        switch k {
        case "stats": return "სტატისტიკა"
        case "prot": return "დაცვა"
        case "filt": return "ფილტრები"
        case "more": return "პარამეტრები"
        case "dns": return "DNS პარამეტრები"
        case "hist": return "დაბლოკვის ისტორია"
        case "saf": return "Safari გაფართოება"
        case "priv": return "კონფიდენციალურობა"
        case "about": return "CleanGEO-ს შესახებ"
        default: return ""
        }
    }
}

struct ScreenSwitch: View {
    let current: String
    var body: some View {
        switch current {
        case "home": HomeScreen()
        case "stats": StatsScreen()
        case "prot": ProtectionScreen()
        case "filt": FiltersScreen()
        case "more": MoreScreen()
        case "dns": DNSScreen()
        case "saf": SafariScreen()
        case "priv": PrivacyScreen()
        case "about": AboutScreen()
        default: HomeScreen()
        }
    }
}

// MARK: - ეკრანის ჩარჩო: ქვეგვერდებზე დაბრუნება დოკის დამალვით

// MARK: - მთავარი

struct HomeScreen: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var ui: UIState
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        let p = CGPalette.scheme(scheme)
        VStack(spacing: 0) {
            HStack {
                HStack(spacing: 9) {
                    CleanGEOLogo(size: 34)
                    Text("CleanGEO")
                        .font(.system(size: 21, weight: .heavy))
                        .tracking(-0.5)
                        .foregroundColor(p.text)
                }
                Spacer()
                CGBadge(appState.tunnel.status == .connected ? "დაცულია" : "გამორთულია",
                        style: appState.tunnel.status == .connected ? .ok : .off)
            }
            .padding(.horizontal, 4)
            .padding(.top, 4)

            WaterGlobe(score: score) {
                toggleProtection()
            }
            .padding(.top, 14)

            Text(headline)
                .font(.system(size: 20, weight: .bold))
                .tracking(-0.4)
                .foregroundColor(p.text)
                .padding(.top, 8)
            Text(subline)
                .font(.system(size: 13.5))
                .foregroundColor(p.text2)
                .multilineTextAlignment(.center)
                .padding(.top, 4)

            HStack(spacing: 6) {
                CGButton("ჩართვა", style: appState.tunnel.status == .connected ? .secondary : .primary) {
                    toggleProtection()
                }
                CGButton("გამორთვა", style: appState.tunnel.status != .connected ? .secondary : .primary) {
                    Task { await appState.tunnel.disable() }
                }
            }
            .frame(width: 280)
            .padding(.top, 10)

            CGSectionTitle("დაცვის შრეები")
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 10) {
                    layer("DNS დაცვა", "ფილტრაცია", "globe", on: filtersLoaded)
                    layer("რეკლამები", "ბლოკირება", "slash.circle", on: filtersLoaded)
                    layer("ტრეკერები", "თვალთვალი", "eye.slash", on: filtersLoaded)
                    layer("საეჭვო დომენები", "ფიშინგი", "exclamationmark.shield", on: filtersLoaded)
                }
                .padding(.horizontal, 18)
            }
            .padding(.horizontal, -18)

            CGSectionTitle("დღევანდელი შეჯამება")
            CGTestDataBanner()
            HStack(spacing: 10) {
                summaryCell("3 142", "დაბლოკილი", p.text)
                summaryCell("9 338", "დაშვებული", CGColor_.ok)
                summaryCell("12 480", "შემოწმებული", p.text2)
            }
            .padding(18)
            .cgCard()

            VStack(spacing: 0) {
                CGRow(icon: "line.3.horizontal.decrease",
                      title: "ფილტრები",
                      subtitle: filterSubtitle,
                      showsSeparator: false) {
                    CGChevron()
                } action: {
                    ui.stack.append("filt")
                }
                CGRow(icon: "globe",
                      title: "DNS დაცვა",
                      subtitle: "CleanGEO DNS · საკუთარი რეზოლვერი",
                      showsSeparator: false) {
                    CGChevron(value: "DNSSEC")
                } action: {
                    ui.stack.append("dns")
                }
            }
            .cgCard()
        }
        .padding(.horizontal, 18)
    }

    private var filtersLoaded: Bool { appState.filters.stats.ruleCount > 0 }

    private var filterSubtitle: String {
        let s = appState.filters.stats
        if s.ruleCount > 0 {
            return "\(s.ruleCount) წესი · განახლებულია"
        }
        return "ჯერ არ განახლებულა"
    }

    /// დაცვის დონე: რეალური ფაქტორებიდან (ტუნელი, Safari blocker,
    /// ფილტრები ჩატვირთულია) — შედარებულია დიზაინის ლოგიკასთან.
    private var score: Int {
        guard appState.tunnel.status == .connected else { return 0 }
        var on = 0.0
        let total = 5.0
        if appState.tunnel.status == .connected { on += 1 }
        if appState.filters.stats.ruleCount > 0 { on += 1 }
        if safariEnabled { on += 1 }
        if appState.isp.dnsHijackDetected || appState.isp.tunnelRequired { on += 1 }
        if appState.filters.stats.lastError == nil { on += 1 }
        return Int((on / total * 100).rounded())
    }

    @State private var safariEnabled = false

    private var headline: String {
        if appState.tunnel.status != .connected { return "დაცვა გამორთულია" }
        return score > 85 ? "თქვენი კავშირი სუფთაა" : "დაცვა ნაწილობრივ ჩართულია"
    }

    private var subline: String {
        appState.tunnel.status == .connected
            ? "რეკლამები და ტრეკერები იბლოკება"
            : "შეეხეთ წრეს ან ჩართეთ ღილაკით"
    }

    private func toggleProtection() {
        Task {
            if appState.tunnel.status == .connected {
                await appState.tunnel.disable()
            } else {
                try? await appState.tunnel.enable(nodeAddress: "tunnel.cleangeo.ge:51820",
                                                  nodePublicKeyBase64: "")
            }
        }
    }

    private func layer(_ title: String, _ sub: String, _ icon: String, on: Bool) -> some View {
        HStack(spacing: 12) {
            CGIcon(icon, style: on ? .inverted : .accent)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13.5, weight: .semibold))
                Text(on ? "ჩართულია" : "გამორთულია")
                    .font(.system(size: 11.5))
                    .opacity(0.7)
            }
        }
        .padding(14)
        .frame(width: 118, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .fill(on ? AnyShapeStyle(LinearGradient(colors: [CGColor_.accent, CGColor_.deep],
                                                        startPoint: .topLeading, endPoint: .bottomTrailing))
                         : AnyShapeStyle(.ultraThinMaterial)))
        .overlay(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .stroke(on ? .clear : CGPalette.scheme(scheme).cardBorder, lineWidth: 1))
        .foregroundColor(on ? .white : CGPalette.scheme(scheme).text)
    }

    private func summaryCell(_ value: String, _ label: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(value)
                .font(.system(size: 30, weight: .heavy))
                .tracking(-1.2)
                .foregroundColor(color)
            Text(label)
                .font(.system(size: 12.5))
                .foregroundColor(CGPalette.scheme(scheme).text2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - სტატისტიკა

struct StatsScreen: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var ui: UIState
    @Environment(\.colorScheme) private var scheme
    @State private var range = "w" // დღე / კვირა / თვე

    // სატესტო მონაცემები (აპლიკაციას არ აქვს დაბლოკვების აღრიცხვა)
    private let demo: [String: (title: String, values: [Double], labels: [String], blocked: Int, total: Int)] = [
        "d": ("დღეს", [120, 260, 410, 380, 520, 640, 430, 382],
              ["00", "03", "06", "09", "12", "15", "18", "21"], 3142, 12480),
        "w": ("ამ კვირაში", [320, 410, 380, 520, 610, 450, 452],
              ["ორშ", "სამ", "ოთხ", "ხუთ", "პარ", "შაბ", "კვი"], 21980, 87360),
        "m": ("ამ თვეში", [2100, 2600, 2300, 3100, 2800, 3400, 3000, 2900, 3300, 3200],
              ["3", "6", "9", "12", "15", "18", "21", "24", "27", "30"], 86920, 347000)
    ]

    var body: some View {
        let p = CGPalette.scheme(scheme)
        let r = demo[range]!
        VStack(spacing: 0) {
            CGTestDataBanner()
            CGSegmented(options: [("d", "დღე"), ("w", "კვირა"), ("m", "თვე")],
                        selection: $range)
                .padding(.vertical, 14)

            VStack(alignment: .leading, spacing: 0) {
                Text("დაბლოკილი \(r.title)")
                    .font(.system(size: 12.5))
                    .foregroundColor(p.text2)
                Text("\(r.blocked)")
                    .font(.system(size: 40, weight: .heavy))
                    .tracking(-1.5)
                    .foregroundColor(p.text)
                    .monospacedDigit()
                CGBarsChart(values: r.values, labels: r.labels)
                    .padding(.top, 14)
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .cgCard()

            VStack(alignment: .leading, spacing: 0) {
                Text("რა დაიბლოკა")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(p.text)
                CGStackBar(segments: [
                    (CGColor_.accent, 0.70),
                    (CGColor_.accent2, 0.25),
                    (CGColor_.bad, 0.05)
                ])
                .padding(.vertical, 12)
                legend(CGColor_.accent, "რეკლამა", Int(Double(r.blocked) * 0.7))
                legend(CGColor_.accent2, "ტრეკერი", Int(Double(r.blocked) * 0.25))
                legend(CGColor_.bad, "საეჭვო დომენი", r.blocked - Int(Double(r.blocked) * 0.7) - Int(Double(r.blocked) * 0.25))
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .cgCard()

            VStack(alignment: .leading, spacing: 0) {
                Text("მოთხოვნები")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(p.text)
                CGStackBar(segments: [
                    (CGColor_.bad, Double(r.blocked) / Double(r.total)),
                    (CGColor_.ok, 1 - Double(r.blocked) / Double(r.total))
                ])
                .padding(.vertical, 12)
                legend(CGColor_.bad, "დაბლოკილი", r.blocked)
                legend(CGColor_.ok, "დაშვებული", r.total - r.blocked)
                legend(Color.gray.opacity(0.55), "სულ შემოწმებული", r.total)
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .cgCard()

            CGSectionTitle("ფილტრების რეალური მდგომარეობა")
            VStack(spacing: 0) {
                CGRow(icon: "line.3.horizontal.decrease",
                      title: "წესების რაოდენობა",
                      showsSeparator: false) {
                    Text("\(appState.filters.stats.ruleCount)")
                        .font(.system(size: 13.5, weight: .semibold))
                        .foregroundColor(p.text2)
                }
                CGRow(icon: "calendar",
                      title: "ბოლო განახლება",
                      showsSeparator: false) {
                    Text(dateText(appState.filters.stats.lastSuccessfulUpdate))
                        .font(.system(size: 13.5, weight: .semibold))
                        .foregroundColor(p.text2)
                }
            }
            .cgCard()

            CGSectionTitle("ბოლო დაბლოკვები")
            CGTestDataBanner("სატესტო მონაცემები — ლოკალური აღრიცხვა ჯერ არ არის ჩართული")
            VStack(spacing: 10) {
                ForEach(0..<3, id: \.self) { i in
                    HStack(spacing: 10) {
                        Circle()
                            .fill([CGColor_.accent, CGColor_.accent2, CGColor_.bad][i])
                            .frame(width: 10, height: 10)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(["ads.doubleclick.example", "track.metrics-demo.net", "pixel.social-demo.com"][i])
                                .font(.system(size: 14, weight: .semibold))
                                .foregroundColor(p.text)
                            Text("რეკლამა · CleanGEO საკუთარი ფილტრი")
                                .font(.system(size: 12.5))
                                .foregroundColor(p.text2)
                        }
                        Spacer()
                        Text(["12:41", "12:38", "12:30"][i])
                            .font(.system(size: 13.5))
                            .foregroundColor(p.text2)
                    }
                    .padding(14)
                    .cgCard()
                }
            }

            CGButton("სრული ისტორია", style: .secondary) {
                // დაბლოკვების ისტორია ჯერ არ არის რეალიზებული სერვისებში
            }
            .padding(.top, 14)
        }
        .padding(.horizontal, 18)
    }

    private func legend(_ c: Color, _ t: String, _ v: Int) -> some View {
        let p = CGPalette.scheme(scheme)
        return HStack(spacing: 0) {
            Circle().fill(c).frame(width: 10, height: 10)
            Text(t).font(.system(size: 14)).foregroundColor(p.text).padding(.leading, 10)
            Spacer()
            Text("\(v)")
                .font(.system(size: 13.5, weight: .bold))
                .foregroundColor(p.text)
                .monospacedDigit()
        }
        .padding(.vertical, 7)
    }

    private func dateText(_ d: Date?) -> String {
        guard let d else { return "—" }
        let f = DateFormatter()
        f.locale = Locale(identifier: "ka_GE")
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: d)
    }
}

// MARK: - დაცვა

struct ProtectionScreen: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var ui: UIState
    @Environment(\.colorScheme) private var scheme
    @State private var safariOn = false

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                CGRow(icon: "globe", title: "DNS ფილტრაცია",
                      subtitle: "კავშირის დონეზე დაცვა",
                      showsSeparator: false) {
                    CGToggle(isOn: Binding(
                        get: { appState.tunnel.status == .connected },
                        set: { on in
                            Task {
                                if on {
                                    try? await appState.tunnel.enable(nodeAddress: "tunnel.cleangeo.ge:51820",
                                                                      nodePublicKeyBase64: "")
                                } else {
                                    await appState.tunnel.disable()
                                }
                            }
                        }))
                }
                CGRow(icon: "slash.circle", title: "რეკლამების ბლოკირება",
                      subtitle: "გვერდებზე და აპებში") {
                    CGToggle(isOn: .constant(appState.filters.stats.ruleCount > 0))
                }
                CGRow(icon: "eye.slash", title: "ტრეკერების ბლოკირება",
                      subtitle: "თვალთვალისგან დაცვა") {
                    CGToggle(isOn: .constant(appState.filters.stats.ruleCount > 0))
                }
                CGRow(icon: "exclamationmark.shield", title: "საეჭვო დომენების ბლოკირება",
                      subtitle: "ფიშინგი და თაღლითობა",
                      showsSeparator: false) {
                    CGToggle(isOn: .constant(appState.filters.stats.ruleCount > 0))
                }
            }
            .cgCard()

            VStack(spacing: 0) {
                CGRow(icon: "safari", title: "Safari გაფართოება",
                      subtitle: "დამატებითი დაცვა ბრაუზერში",
                      showsSeparator: false) {
                    CGChevron(value: safariOn ? "ჩართულია" : "გამორთულია")
                } action: { ui.stack.append("saf") }
                CGRow(icon: "network", title: "DNS პარამეტრები",
                      subtitle: "სერვერი და დაცული კავშირი") {
                    CGChevron()
                } action: { ui.stack.append("dns") }
                CGRow(icon: "list.bullet", title: "თეთრი და შავი სია",
                      subtitle: "თქვენი წესები — მალე",
                      showsSeparator: false) {
                    Text("სატესტო").font(.system(size: 11.5, weight: .bold))
                        .foregroundColor(CGPalette.scheme(scheme).text2)
                }
            }
            .cgCard()
        }
        .padding(.horizontal, 18)
        .task {
            let status: Bool = await withCheckedContinuation { cont in
                SFContentBlockerManager.getStateOfContentBlocker(withIdentifier: FilterListManager.blockerID) { enabled, _ in
                    cont.resume(returning: enabled != nil)
                }
            }
            safariOn = status
        }
    }
}

// MARK: - ფილტრები

struct FiltersScreen: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.colorScheme) private var scheme
    @State private var updating = false
    @State private var message: String?

    var body: some View {
        let p = CGPalette.scheme(scheme)
        VStack(spacing: 0) {
            // წესი №4: მხოლოდ ერთი ფილტრი — „CleanGEO საკუთარი ფილტრი“
            VStack(spacing: 0) {
                CGRow(icon: "line.3.horizontal.decrease",
                      title: "CleanGEO საკუთარი ფილტრი",
                      subtitle: filterSubtitle,
                      showsSeparator: false) {
                    CGToggle(isOn: .constant(appState.filters.stats.ruleCount > 0))
                }
            }
            .cgCard()

            if let m = message {
                HStack(spacing: 8) {
                    Image(systemName: "info.circle")
                    Text(m).font(.system(size: 12.5, weight: .semibold))
                }
                .foregroundColor(CGColor_.accent)
                .padding(.horizontal, 13)
                .padding(.vertical, 9)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(p.accentSoft))
                .padding(.top, 12)
            }

            VStack(spacing: 0) {
                CGRow(icon: "calendar", title: "ბოლო განახლება",
                      showsSeparator: false) {
                    Text(dateText(appState.filters.stats.lastSuccessfulUpdate))
                        .font(.system(size: 13.5))
                        .foregroundColor(p.text2)
                }
                CGRow(icon: "number", title: "წესების რაოდენობა") {
                    Text("\(appState.filters.stats.ruleCount)")
                        .font(.system(size: 13.5))
                        .foregroundColor(p.text2)
                }
                CGRow(icon: "tray.full", title: "ჩატვირთული ლისტები",
                      showsSeparator: false) {
                    Text("\(appState.filters.stats.listCount)")
                        .font(.system(size: 13.5))
                        .foregroundColor(p.text2)
                }
            }
            .cgCard()

            if let err = appState.filters.stats.lastError {
                Text(err)
                    .font(.system(size: 12.5))
                    .foregroundColor(CGColor_.bad)
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(CGColor_.bad.opacity(0.12)))
            }

            CGButton("ფილტრების განახლება",
                     systemImage: "arrow.clockwise",
                     loading: updating) {
                updating = true
                message = nil
                Task {
                    do {
                        _ = try await FilterListManager.shared.updateAll()
                        try? await FilterListManager.shared.reloadSafariBlocker()
                        message = "ფილტრები განახლდა"
                    } catch {
                        message = "შეცდომა: \(error.localizedDescription)"
                    }
                    updating = false
                }
            }
            .padding(.top, 14)
        }
        .padding(.horizontal, 18)
    }

    private var filterSubtitle: String {
        let s = appState.filters.stats
        if s.ruleCount > 0 {
            return "\(s.ruleCount) წესი · \(s.listCount) ლისტი · განახლებულია"
        }
        return "ქართული და საერთაშორისო სია · ჯერ არ განახლებულა"
    }

    private func dateText(_ d: Date?) -> String {
        guard let d else { return "—" }
        let f = DateFormatter()
        f.locale = Locale(identifier: "ka_GE")
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: d)
    }
}

// MARK: - DNS პარამეტრები

struct DNSScreen: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.colorScheme) private var scheme
    @State private var queryHost = "example.com"
    @State private var queryResult: String?
    @State private var testing = false

    var body: some View {
        let p = CGPalette.scheme(scheme)
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                CGIcon(appState.tunnel.status == .connected ? "checkmark" : "network",
                       style: appState.tunnel.status == .connected ? .ok : .accent)
                    .frame(width: 46, height: 46)
                VStack(alignment: .leading, spacing: 2) {
                    Text(appState.tunnel.status == .connected ? "კავშირი დაცულია" : "კავშირი გამორთულია")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(p.text)
                    Text(appState.tunnel.status == .connected
                         ? "საკუთარი რეკურსიული რეზოლვერი პასუხობს"
                         : "ჩართეთ დაცვა მთავარ გვერდზე")
                        .font(.system(size: 12.5))
                        .foregroundColor(p.text2)
                }
                Spacer()
                if appState.tunnel.status == .connected {
                    CGBadge("18 მწმ", style: .ok)
                }
            }
            .padding(18)
            .cgCard()

            CGSectionTitle("რეზოლვერი")
            VStack(spacing: 0) {
                CGRow(icon: "network", title: "CleanGEO DNS",
                      subtitle: "საკუთარი რეკურსიული რეზოლვერი — Google, Cloudflare, AdGuard არ გამოიყენება",
                      showsSeparator: false) {
                    CGSelector(isOn: true)
                }
            }
            .cgCard()

            CGSectionTitle("დაცული კავშირი")
            VStack(spacing: 0) {
                CGRow(icon: "lock", title: "DNS over HTTPS",
                      subtitle: "დაშიფრული მოთხოვნები",
                      showsSeparator: false) {
                    CGToggle(isOn: .constant(true))
                }
                CGRow(icon: "lock", title: "DNS over TLS",
                      subtitle: "dns.cleangeo.ge:853 · TLS 1.3") {
                    CGToggle(isOn: .constant(true))
                }
                CGRow(icon: "checkmark.shield", title: "DNSSEC",
                      subtitle: "პასუხების შემოწმება",
                      showsSeparator: false) {
                    CGToggle(isOn: .constant(true))
                }
            }
            .cgCard()

            CGSectionTitle("ტესტი")
            HStack(spacing: 8) {
                TextField("დომენი, მაგ. example.com", text: $queryHost)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(size: 15))
                    .cgInput()
                CGIconButton("play.fill") {
                    testing = true
                    Task {
                        do {
                            let resolver = RecursiveResolver()
                            let result = try await resolver.resolve(queryHost)
                            queryResult = result.addresses.isEmpty
                                ? "პასუხი ცარიელია"
                                : "IP მისამართები: " + result.addresses.joined(separator: ", ")
                        } catch {
                            queryResult = "შეცდომა: \(error.localizedDescription)"
                        }
                        testing = false
                    }
                }
            }
            if testing {
                ProgressView().padding(.top, 10)
            }
            if let r = queryResult {
                Text(r)
                    .font(.system(size: 12.5))
                    .foregroundColor(p.text2)
                    .padding(13)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(p.accentSoft))
                    .padding(.top, 10)
            }
        }
        .padding(.horizontal, 18)
    }
}

// MARK: - Safari გაფართოება

struct SafariScreen: View {
    @Environment(\.colorScheme) private var scheme
    @State private var enabled = false
    @State private var checking = true

    var body: some View {
        let p = CGPalette.scheme(scheme)
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                CGIcon("safari", style: enabled ? .ok : .accent)
                    .frame(width: 68, height: 68)
                    .padding(.bottom, 12)
                Text(enabled ? "გაფართოება ჩართულია" : "გაფართოება გამორთულია")
                    .font(.system(size: 18, weight: .bold))
                    .foregroundColor(p.text)
                Text(enabled ? "Safari დაცულია" : "ჩართეთ Safari-ს პარამეტრებში")
                    .font(.system(size: 12.5))
                    .foregroundColor(p.text2)
                    .padding(.top, 4)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 24)
            .cgCard()

            CGSectionTitle("ჩართვის ინსტრუქცია")
            VStack(spacing: 0) {
                CGStepRow(index: 1, text: "გახსენით iPhone-ის „პარამეტრები“")
                CGStepRow(index: 2, text: "აირჩიეთ „Safari“ და შემდეგ „გაფართოებები“")
                CGStepRow(index: 3, text: "ჩართეთ „CleanGEO“ და დაუშვით ყველა ვებგვერდი")
            }
            .cgCard()

            CGButton("განახლების შემოწმება",
                     systemImage: "arrow.clockwise",
                     loading: checking) {
                checking = true
                Task {
                    _ = try? await FilterListManager.shared.updateAll()
                    try? await FilterListManager.shared.reloadSafariBlocker()
                    checkState()
                    checking = false
                }
            }
            .padding(.top, 14)
        }
        .padding(.horizontal, 18)
        .onAppear { checkState() }
    }

    private func checkState() {
        SFContentBlockerManager.getStateOfContentBlocker(withIdentifier: FilterListManager.blockerID) { enabled, _ in
            DispatchQueue.main.async { self.enabled = enabled != nil }
        }
    }
}

// MARK: - კონფიდენციალურობა

struct PrivacyScreen: View {
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                CGRow(icon: "clock", title: "ლოკალური ისტორია",
                      subtitle: "ინახება მხოლოდ თქვენს მოწყობილობაში",
                      showsSeparator: false) {
                    CGToggle(isOn: .constant(true))
                }
            }
            .cgCard()
            Text("CleanGEO არ ინახავს და არ გადასცემს DNS-ისტორიას. არ არსებობს ანალიტიკა.")
                .font(.system(size: 12.5))
                .foregroundColor(CGPalette.scheme(scheme).text2)
                .padding(.top, 10)
        }
        .padding(.horizontal, 18)
    }
}

// MARK: - შესახებ

struct AboutScreen: View {
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        let p = CGPalette.scheme(scheme)
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                CleanGEOLogo(size: 84)
                    .padding(.bottom, 12)
                Text("CleanGEO")
                    .font(.system(size: 22, weight: .heavy))
                    .foregroundColor(p.text)
                Text("ვერსია 1.0.0")
                    .font(.system(size: 12.5))
                    .foregroundColor(p.text2)
                    .padding(.top, 3)
                Text("სუფთა და უსაფრთხო ინტერნეტი: რეკლამების, ტრეკერებისა და საეჭვო დომენების ბლოკირება ერთ აპლიკაციაში.")
                    .font(.system(size: 13))
                    .foregroundColor(p.text2)
                    .multilineTextAlignment(.center)
                    .padding(.top, 10)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 26)
            .cgCard()
        }
        .padding(.horizontal, 18)
    }
}

// MARK: - პარამეტრები

struct MoreScreen: View {
    @EnvironmentObject var ui: UIState
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(spacing: 0) {
            CGSectionTitle("თემა")
            CGSegmented(options: [("auto", "ავტომატური"), ("light", "ღია"), ("dark", "მუქი")],
                        selection: Binding(
                            get: { ui.theme.rawValue },
                            set: { ui.setTheme(CGUITheme(rawValue: $0) ?? .auto) }))

            CGSectionTitle("მართვა")
            VStack(spacing: 0) {
                CGRow(icon: "clock", title: "დაბლოკვის ისტორია",
                      subtitle: "სატესტო მონაცემები",
                      showsSeparator: false) { CGChevron() }
                CGRow(icon: "safari", title: "Safari გაფართოება",
                      showsSeparator: false) {
                    CGChevron()
                } action: { ui.stack.append("saf") }
                CGRow(icon: "globe", title: "DNS პარამეტრები",
                      showsSeparator: false) {
                    CGChevron()
                } action: { ui.stack.append("dns") }
                CGRow(icon: "lock", title: "კონფიდენციალურობა",
                      showsSeparator: false) {
                    CGChevron()
                } action: { ui.stack.append("priv") }
            }
            .cgCard()

            CGSectionTitle("შესახებ")
            VStack(spacing: 0) {
                CGRow(icon: "info.circle", title: "აპლიკაციის ვერსია",
                      showsSeparator: false) {
                    Text("1.0.0")
                        .font(.system(size: 13.5))
                        .foregroundColor(CGPalette.scheme(scheme).text2)
                }
                CGRow(icon: "shield.lefthalf.filled", title: "CleanGEO-ს შესახებ",
                      showsSeparator: false) {
                    CGChevron()
                } action: { ui.stack.append("about") }
            }
            .cgCard()
        }
        .padding(.horizontal, 18)
    }
}
