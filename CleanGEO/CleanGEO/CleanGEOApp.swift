import SwiftUI

@main
struct CleanGEOApp: App {
    init() { FilterListManager.register(); FilterListManager.schedule() }
    var body: some Scene {
        WindowGroup {
            WebHostView().ignoresSafeArea().task {
                await TunnelManager.shared.load()
                await FilterListManager.shared.updateIfStale()
            }
        }
    }
}
