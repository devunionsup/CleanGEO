//
//  CleanGEOApp.swift
//  CleanGEO
//
//  App entry point. Launches in Georgian; performs a filter update check
//  on launch as required by the spec.
//

import SwiftUI
import BackgroundTasks

@main
struct CleanGEOApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var uiState = UIState()

    init() {
        // Georgian is the app's primary and only user-facing language.
        // Localizable.strings carries the Georgian text; this is belt and
        // braces in case the system language differs.
        UserDefaults.standard.set(["ka"], forKey: "AppleLanguages")
        _registerBackgroundTasks()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(appState)
                .environmentObject(uiState)
                .environment(\.locale, .init(identifier: "ka"))
                .tint(Theme.accent)
        }
    }

    private func _registerBackgroundTasks() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: BackgroundRefresh.taskID,
                                        using: nil) { task in
            BackgroundRefresh.handle(task: task as! BGAppRefreshTask)
        }
    }
}

// MARK: - App state

@MainActor
final class AppState: ObservableObject {
    @Published var filters = FilterListManager.shared
    @Published var tunnel = TunnelManager.shared
    @Published var isp = ISPBlockDetector.shared

    init() {
        // Check the schedule on launch too (spec: additional check at startup).
        Task.detached(priority: .utility) { [weak self] in
            if FilterListManager.shared.scheduledUpdateDue() {
                _ = try? await FilterListManager.shared.updateAll()
            }
            _ = self
        }
    }
}

// MARK: - Background refresh

public enum BackgroundRefresh {
    public static let taskID = "ge.cleangeo.app.filters.refresh"

    /// iOS does not guarantee exact execution; the app also checks on launch
    /// and after any foregrounding (see AppState / scenePhase in RootView).
    public static func scheduleNext(schedule: UpdateSchedule) {
        let request = BGAppRefreshTaskRequest(identifier: taskID)
        // Submit for the next due slot.
        request.earliestBeginDate = nextDueDate(schedule: schedule)
        try? BGTaskScheduler.shared.submit(request)
    }

    static func nextDueDate(schedule: UpdateSchedule, now: Date = Date()) -> Date? {
        guard !schedule.times.isEmpty else { return nil }
        let cal = Calendar.current
        let comps = cal.dateComponents([.hour, .minute], from: now)
        let nowMin = comps.hour! * 60 + comps.minute!
        var best: (min: Int, date: Date)? = nil
        for t in schedule.times {
            let dueMin = t.hour * 60 + t.minute
            var delta = dueMin - nowMin
            if delta <= 0 { delta += 24 * 60 }
            let date = cal.date(byAdding: .minute, value: delta, to: now)!
            if best == nil || delta < best!.min {
                best = (delta, date)
            }
        }
        return best?.date
    }

    /// Runs when iOS grants the background slot.
    static func handle(task: BGAppRefreshTask) {
        let work = Task {
            do {
                _ = try await FilterListManager.shared.updateAll()
                task.setTaskCompleted(success: true)
            } catch {
                // Previous working filters remain untouched on failure.
                task.setTaskCompleted(success: false)
            }
            scheduleNext(schedule: FilterListManager.shared.schedule)
        }
        task.expirationHandler = { work.cancel() }
    }
}
