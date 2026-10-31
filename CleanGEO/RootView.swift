//
//  RootView.swift
//  CleanGEO
//
//  Tab-based root: მთავარი (home), ფილტრები, DNS, განრიგი, პარამეტრები.
//  Every user-facing string is Georgian.
//

import SwiftUI
import SafariServices

struct RootView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.scenePhase) var scenePhase

    var body: some View {
        TabView {
            HomeView()
                .tabItem { Label("მთავარი", systemImage: "shield.lefthalf.filled") }
            FiltersView()
                .tabItem { Label("ფილტრები", systemImage: "doc.badge.gearshape") }
            ScheduleView()
                .tabItem { Label("განრიგი", systemImage: "clock.badge.checkmark") }
            DNSView()
                .tabItem { Label("DNS", systemImage: "network") }
            SettingsView()
                .tabItem { Label("პარამეტრები", systemImage: "gearshape") }
        }
        .preferredColorScheme(.dark)
        .onChange(of: scenePhase) { phase in
            if phase == .active {
                // Launch/foreground check.
                Task {
                    _ = try? await FilterListManager.shared.updateAllIfDue()
                    try? await FilterListManager.shared.reloadSafariBlocker()
                }
            }
        }
    }
}

// MARK: - Home

struct HomeView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 16) {
                    heroCard
                    safariCard
                    dnsCard
                    ispCard
                }
                .padding()
            }
            .background(Theme.backgroundDeep.ignoresSafeArea())
            .navigationTitle("CleanGEO")
            .navigationBarTitleDisplayMode(.inline)
        }
        .navigationViewStyle(.stack)
    }

    private var heroCard: some View {
        VStack(spacing: 14) {
            CleanGEOLogo(size: 88)
            Text("CleanGEO")
                .font(.system(size: 30, weight: .bold, design: .rounded))
            Text("რეკლამის ბლოკირება, საკუთარი DNS და პრივატულობის დაცვა — ერთ აპლიკაციაში")
                .font(.subheadline)
                .foregroundColor(Theme.textSecondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 26)
        .cleangeoCard()
    }

    private var safariCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "safari")
                    .font(.title2)
                Text("Safari-ს დაცვა")
                    .font(.headline)
                Spacer()
                SafariBlockerStatusView()
            }
            Text("გააქტიურეთ გაფართოება ერთხელ: პარამეტრები → Safari → გაფართოებები → CleanGEO → ჩართეთ.")
                .font(.footnote)
                .foregroundColor(Theme.textSecondary)
            SafariInstructions()
        }
        .padding()
        .cleangeoCard()
    }

    private var dnsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "network")
                    .font(.title2)
                Text("CleanGEO DNS")
                    .font(.headline)
                Spacer()
                StatusPill(text: appState.tunnel.statusText, color: appState.tunnel.status == .connected ? Theme.success : Theme.warning)
            }
            Text("საკუთარი რეკურსიული რეზოლვერი DNSSEC-ით, DoH და DoT შიფრაციით. Google-ის, Cloudflare-ის ან AdGuard-ის DNS არ გამოიყენება.")
                .font(.footnote)
                .foregroundColor(Theme.textSecondary)
            NavigationLink("DNS-ის პარამეტრები") { DNSView() }
                .font(.subheadline.weight(.semibold))
        }
        .padding()
        .cleangeoCard()
    }

    private var ispCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: appState.isp.tunnelRequired ? "exclamationmark.triangle.fill" : "checkmark.seal.fill")
                    .font(.title2)
                    .foregroundColor(appState.isp.tunnelRequired ? Theme.warning : Theme.success)
                Text("ინტერნეტ-პროვაიდერის ჩარევა")
                    .font(.headline)
                Spacer()
                Button("შემოწმება") {
                    Task { await appState.isp.check() }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
            Text(appState.isp.dnsHijackDetected
                 ? "აღმოჩენილია DNS-ჩარევა: პროვაიდერი ცვლის პასუხებს."
                 : "DNS-ჩარევა არ ფიქსირდება.")
                .font(.footnote)
                .foregroundColor(Theme.textSecondary)
            Text(appState.isp.ipBlockDetected
                 ? "აღმოჩენილია IP-დონის შეზღუდვა — რეკომენდირებულია ტუნელის ჩართვა."
                 : "IP-დონის შეზღუდვა არ ფიქსირდება.")
                .font(.footnote)
                .foregroundColor(Theme.textSecondary)
        }
        .padding()
        .cleangeoCard()
    }
}

struct SafariBlockerStatusView: View {
    @State private var enabled = false

    var body: some View {
        Group {
            if enabled {
                StatusPill(text: "ჩართულია", color: Theme.success)
            } else {
                StatusPill(text: "გამორთულია", color: Theme.warning)
            }
        }
        .task {
            let status: Bool = await withCheckedContinuation { cont in
                SFContentBlockerManager.getStateOfContentBlocker(withIdentifier: FilterListManager.blockerID) { enabled, _ in
                    cont.resume(returning: enabled != nil)
                }
            }
            enabled = status
        }
    }
}

struct SafariInstructions: View {
    @State private var open = false
    var body: some View {
        Button {
            open.toggle()
        } label: {
            Label(open ? "დახურე ინსტრუქცია" : "როგორ ჩავრთო?", systemImage: open ? "chevron.up" : "chevron.down")
                .font(.footnote.weight(.semibold))
        }
        if open {
            VStack(alignment: .leading, spacing: 6) {
                Text("1. გახსენით პარამეტრები → Safari → გაფართოებები.")
                Text("2. აირჩიეთ CleanGEO და ჩართეთ ნებართვა.")
                Text("3. დაბრუნდით აქ და დააჭირეთ „განახლება“ — ფილტრები დაყენდება ავტომატურად.")
            }
            .font(.footnote)
            .foregroundColor(Theme.textSecondary)
            Button("განახლება ახლავე") {
                Task {
                    _ = try? await FilterListManager.shared.updateAll()
                    try? await FilterListManager.shared.reloadSafariBlocker()
                }
            }
            .buttonStyle(.borderedProminent)
        }
    }
}

// MARK: - Filters

struct FiltersView: View {
    @EnvironmentObject var appState: AppState
    @State private var updating = false
    @State private var message: String?

    var body: some View {
        NavigationView {
            List {
                Section("სტატისტიკა") {
                    LabeledRow(label: "ბოლო განახლება", value: dateText(appState.filters.stats.lastSuccessfulUpdate))
                    LabeledRow(label: "წესების რაოდენობა", value: "\(appState.filters.stats.ruleCount)")
                    LabeledRow(label: "ჩატვირთული ლისტები", value: "\(appState.filters.stats.listCount)")
                    if let err = appState.filters.stats.lastError {
                        LabeledRow(label: "ბოლო შეცდომა", value: err)
                    }
                }
                Section("ბლოკ-ლისტები") {
                    ForEach(appState.filters.sources) { s in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(s.name).font(.body)
                            Text(s.url).font(.caption2).foregroundColor(Theme.textSecondary)
                        }
                    }
                }
                Section {
                    Button {
                        updating = true
                        Task {
                            do {
                                let r = try await FilterListManager.shared.updateAll()
                                try? await FilterListManager.shared.reloadSafariBlocker()
                                message = "განახლდა: \(r.rules) წესი, \(r.lists) ლისტი"
                            } catch {
                                message = "შეცდომა: \(error.localizedDescription)"
                            }
                            updating = false
                        }
                    } label: {
                        HStack {
                            if updating { ProgressView().padding(.trailing, 6) }
                            Text("განახლება ახლავე")
                        }
                    }
                    .disabled(updating)
                } footer: {
                    Text("წარუმატებელი განახლების დროს წინა მომუშავი ვერსია რჩება უცვლელად.")
                }
                if let m = message {
                    Text(m).font(.footnote).foregroundColor(Theme.textSecondary)
                }
            }
            .navigationTitle("ფილტრები")
        }
        .navigationViewStyle(.stack)
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

struct LabeledRow: View {
    let label: String
    let value: String
    var body: some View {
        HStack {
            Text(label)
            Spacer()
            Text(value).foregroundColor(Theme.textSecondary)
        }
    }
}

// MARK: - Schedule

struct ScheduleView: View {
    @EnvironmentObject var appState: AppState
    @State private var times: [UpdateSchedule.ScheduleTime] = UpdateSchedule.default.times

    var body: some View {
        NavigationView {
            List {
                Section {
                    ForEach(times.indices, id: \.self) { i in
                        DatePicker("დრო \(i + 1)",
                                   selection: binding(for: i),
                                   displayedComponents: .hourAndMinute)
                    }
                    .onDelete { offsets in
                        times.remove(atOffsets: offsets)
                        save()
                    }
                } header: {
                    Text("დღეში ოთხჯერ განახლება")
                } footer: {
                    Text("iOS არ იძლევა ზუსტი ფონური გაშვების გარანტიას — აპლიკაცია ასევე ამოწმებს განრიგს გახსნისას.")
                }
                Section {
                    if times.count < 4 {
                        Button("დაამატე დრო") {
                            times.append(.init(hour: 12, minute: 0))
                            save()
                        }
                    }
                }
            }
            .navigationTitle("განრიგი")
            .onAppear { times = FilterListManager.shared.schedule.times }
        }
        .navigationViewStyle(.stack)
    }

    private func binding(for i: Int) -> Binding<Date> {
        Binding(
            get: {
                let t = times[i]
                return Calendar.current.date(from: DateComponents(hour: t.hour, minute: t.minute)) ?? Date()
            },
            set: { d in
                let c = Calendar.current.dateComponents([.hour, .minute], from: d)
                times[i] = .init(hour: c.hour!, minute: c.minute!)
                save()
            })
    }

    private func save() {
        let s = UpdateSchedule(times: times)
        FilterListManager.shared.setSchedule(s)
        BackgroundRefresh.scheduleNext(schedule: s)
    }
}

// MARK: - DNS

struct DNSView: View {
    @EnvironmentObject var appState: AppState
    @State private var queryHost = "example.com"
    @State private var queryResult: String?
    @State private var testing = false

    var body: some View {
        Form {
            Section("ტუნელი") {
                Toggle("CleanGEO VPN", isOn: Binding(
                    get: { appState.tunnel.status == .connected },
                    set: { on in
                        Task {
                            if on {
                                try? await appState.tunnel.enable(nodeAddress: "tunnel.cleangeo.ge:51820",
                                                                  nodePublicKeyBase64: "")
                            } else {
                                try? await appState.tunnel.disable()
                            }
                        }
                    }))
                Text("ტუნელი იყენებს NetworkExtension-ს; პირველი ჩართვისას iOS ითხოვს ნებართვას.")
                    .font(.footnote).foregroundColor(Theme.textSecondary)
            }
            Section("DoH / DoT") {
                LabeledRow(label: "DoH მისამართი", value: "https://dns.cleangeo.ge/dns-query")
                LabeledRow(label: "DoT მისამართი", value: "dns.cleangeo.ge:853")
                LabeledRow(label: "TLS", value: "TLS 1.3")
            }
            Section("ტესტი") {
                TextField("დომენი", text: $queryHost)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button(testing ? "მიმდინარეობს…" : "შემოწმება") {
                    testing = true
                    Task {
                        do {
                            let r = try await ResolverFacade.shared.resolve(host: queryHost)
                            queryResult = r
                        } catch {
                            queryResult = "შეცდომა: \(error.localizedDescription)"
                        }
                        testing = false
                    }
                }
                .disabled(testing || queryHost.isEmpty)
                if let r = queryResult {
                    Text(r).font(.footnote).foregroundColor(Theme.textSecondary)
                }
            }
        }
        .navigationTitle("DNS")
    }
}

/// Thin async facade used by the UI to resolve through the CleanGEO stack.
public final class ResolverFacade {
    public static let shared = ResolverFacade()
    private let resolver = RecursiveResolver()

    public func resolve(host: String) async throws -> String {
        let result = try await resolver.resolve(host, type: .a)
        let sec = result.dnssecValidated ? " — DNSSEC ✓" : ""
        return result.addresses.joined(separator: ", ") + sec
    }
}

// MARK: - Settings

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var showPrivacy = false

    var body: some View {
        NavigationView {
            Form {
                Section("პრივატულობა") {
                    Toggle("ისტორიის შენახვა", isOn: .constant(false))
                        .disabled(true)
                    Text("CleanGEO არ ინახავს და არ გადასცემს DNS-ისტორიას. არ არსებობს ანალიტიკა.")
                        .font(.footnote).foregroundColor(Theme.textSecondary)
                }
                Section("უსაფრთხოება") {
                    LabeledRow(label: "ფილტრების გადამოწმება", value: "SHA-256 + HTTPS")
                    LabeledRow(label: "DNSSEC", value: "ჩართულია")
                    LabeledRow(label: "0x20 / შემთხვევითი ID", value: "ჩართულია")
                }
                Section("შესახებ") {
                    LabeledRow(label: "ვერსია", value: "1.0")
                    Text("CleanGEO — შექმნილია საქართველოსთვის 🇬🇪")
                        .font(.footnote).foregroundColor(Theme.textSecondary)
                }
            }
            .navigationTitle("პარამეტრები")
        }
        .navigationViewStyle(.stack)
    }
}
