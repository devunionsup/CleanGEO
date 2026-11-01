import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack(spacing: 16) {
            Text("CleanGEO")
                .font(.largeTitle)
                .bold()
            Text("როგორ ჩავრთოთ:")
                .font(.headline)
            Text("პარამეტრები → Safari → გაფართოებები → CleanGEO — ჩართეთ და დართეთ წვდომა საიტებზე.")
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
        .padding()
    }
}
