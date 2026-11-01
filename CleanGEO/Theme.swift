//
//  Theme.swift
//  CleanGEO
//
//  დიზაინ-სისტემა (v3): მინისებრი ბარათები, წყლის სფერო, მცურავი დოკი,
//  სეგმენტები, გადამრთველები, ღია/მუქი თემა.
//  ფერები ზუსტად იმეორებს დიზაინის CSS ცვლადებს (#1a73ff, #5eb0ff, #0b3fb8,
//  #12b886, #f04f5f, ღია: #f3f8ff/#0a1b33, მუქი: #050d1a/#eef4ff).
//

import SwiftUI

// MARK: - ძირითადი ფერები (თემისგან დამოუკიდებელი)

public enum CGColor_ {
    /// --ac #1a73ff
    public static let accent  = Color(red: 0x1a / 255, green: 0x73 / 255, blue: 0xff / 255)
    /// --a2 #5eb0ff
    public static let accent2 = Color(red: 0x5e / 255, green: 0xb0 / 255, blue: 0xff / 255)
    /// --dp #0b3fb8
    public static let deep    = Color(red: 0x0b / 255, green: 0x3f / 255, blue: 0xb8 / 255)
    /// --ok #12b886
    public static let ok      = Color(red: 0x12 / 255, green: 0xb8 / 255, blue: 0x86 / 255)
    /// --bd #f04f5f
    public static let bad     = Color(red: 0xf0 / 255, green: 0x4f / 255, blue: 0x5f / 255)
}

// MARK: - რესპონსიული layout კონსტანტები (ყველა iPhone მოდელისთვის ერთი სისტემა)
//
// ფიქსირებული ზომები მხოლოდ კონტროლებისთვისაა (ღილაკები, ხატულები);
// ყველაფერი, რაც ეკრანზე უნდა ადაპტირდეს, size class-ებიდან ითვლება.

public enum CGLayout {
    /// წყლის სფეროს დიამეტრი Portrait-ში
    public static let globeSize: CGFloat = 228
    /// სფერო მცირე სიმაღლის ეკრანზე (Landscape)
    public static let globeSizeCompact: CGFloat = 156
    /// სვეტებიანი დიაგრამის მაქს. სიმაღლე
    public static let barsMaxHeight: Double = 130
    public static let barsMaxHeightCompact: Double = 96
    /// მცურავი დოკის სიმაღლე
    public static let dockHeight: CGFloat = 68
    public static let dockHeightCompact: CGFloat = 62
    /// დოკის ცენტრალური ღილაკი
    public static let dockCenterSize: CGFloat = 64
    public static let dockCenterSizeCompact: CGFloat = 52
    /// დაცვის ფენების ბარათის სიგანე — დიაპაზონი, არა ფიქსირებული მნიშვნელობა
    public static let layerCardMin: CGFloat = 112
    public static let layerCardMax: CGFloat = 132
    /// სქროლის ქვედა სივრცე: დოკი + Home Indicator-ის ზონა
    public static let dockBottomSpace: CGFloat = 132
}

// MARK: - თემაზე დამოკიდებული პალიტრა

public struct CGPalette {
    public let bg: Color          // --bg
    public let card: Color        // --cd
    public let cardBorder: Color  // --cb
    public let text: Color        // --tx
    public let text2: Color       // --t2
    public let accentSoft: Color  // --as
    public let separator: Color   // --sp
    public let dock: Color        // --gl
    public let water: Color       // --wt
    public let water2: Color      // მეორე ტალღა

    public static func scheme(_ s: ColorScheme) -> CGPalette {
        if s == .dark {
            return CGPalette(
                bg: Color(red: 0x05 / 255, green: 0x0d / 255, blue: 0x1a / 255),
                card: Color(red: 22 / 255, green: 36 / 255, blue: 60 / 255).opacity(0.68),
                cardBorder: Color.white.opacity(0.08),
                text: Color(red: 0xee / 255, green: 0xf4 / 255, blue: 0xff / 255),
                text2: Color(red: 0x8d / 255, green: 0xa0 / 255, blue: 0xbd / 255),
                accentSoft: Color(red: 60 / 255, green: 140 / 255, blue: 255 / 255).opacity(0.18),
                separator: Color.white.opacity(0.08),
                dock: Color(red: 14 / 255, green: 24 / 255, blue: 42 / 255).opacity(0.74),
                water: Color(red: 60 / 255, green: 150 / 255, blue: 255 / 255).opacity(0.45),
                water2: Color(red: 60 / 255, green: 150 / 255, blue: 255 / 255).opacity(0.30))
        }
        return CGPalette(
            bg: Color(red: 0xf3 / 255, green: 0xf8 / 255, blue: 0xff / 255),
            card: Color.white.opacity(0.74),
            cardBorder: Color.white.opacity(0.9),
            text: Color(red: 0x0a / 255, green: 0x1b / 255, blue: 0x33 / 255),
            text2: Color(red: 0x62 / 255, green: 0x74 / 255, blue: 0x8f / 255),
            accentSoft: CGColor_.accent.opacity(0.10),
            separator: Color(red: 10 / 255, green: 40 / 255, blue: 90 / 255).opacity(0.08),
            dock: Color.white.opacity(0.72),
            water: CGColor_.accent.opacity(0.38),
            water2: CGColor_.accent2.opacity(0.30))
    }
}

// MARK: - უკუთავსება ძველი API-სთვის (CleanGEOApp იყენებს)

public enum Theme {
    public static let accent = CGColor_.accent
    public static let accent2 = CGColor_.accent2
    public static let backgroundDeep = Color(red: 0x05, green: 0x0d, blue: 0x1a)
    public static let surface = Color(red: 22 / 255, green: 36 / 255, blue: 60 / 255)
    public static let surfaceHigh = Color(red: 14 / 255, green: 24 / 255, blue: 42 / 255)
    public static let textPrimary = Color.white
    public static let textSecondary = Color.white.opacity(0.62)
    public static let success = CGColor_.ok
    public static let warning = CGColor_.accent2
    public static let danger = CGColor_.bad
    public static let heroGradient = LinearGradient(
        colors: [CGColor_.accent2, CGColor_.deep],
        startPoint: .topLeading, endPoint: .bottomTrailing)
    public static let cardGradient = LinearGradient(
        colors: [surface, surfaceHigh], startPoint: .top, endPoint: .bottom)
}

// MARK: - აპლიკაციის ფონი (რადიალური გრადიენტები)

public struct CGAppBackground: View {
    @Environment(\.colorScheme) private var scheme
    public init() {}
    public var body: some View {
        let p = CGPalette.scheme(scheme)
        ZStack {
            p.bg
            Circle().fill(CGColor_.accent.opacity(0.25)).blur(radius: 60)
                .frame(width: 500, height: 500)
                .offset(x: 150, y: -170)
            Circle().fill(CGColor_.accent2.opacity(0.22)).blur(radius: 60)
                .frame(width: 420, height: 420)
                .offset(x: -170, y: -60)
        }
        .ignoresSafeArea()
    }
}

// MARK: - მინისებრი ბარათი (.cd)

public struct CGCardStyle: ViewModifier {
    @Environment(\.colorScheme) private var scheme
    public func body(content: Content) -> some View {
        let p = CGPalette.scheme(scheme)
        content
            .background(
                RoundedRectangle(cornerRadius: 26, style: .continuous)
                    .fill(.ultraThinMaterial)
                    .overlay(
                        RoundedRectangle(cornerRadius: 26, style: .continuous)
                            .fill(p.card))
                    .overlay(
                        RoundedRectangle(cornerRadius: 26, style: .continuous)
                            .stroke(p.cardBorder, lineWidth: 1)))
            .shadow(color: Color(red: 20 / 255, green: 70 / 255, blue: 160 / 255).opacity(scheme == .dark ? 0.35 : 0.09),
                    radius: 15, y: 10)
    }
}

public extension View {
    /// მინისებრი ბარათი — დიზაინის .cd კლასის ეკვივალენტი.
    func cgCard() -> some View { modifier(CGCardStyle()) }
}

// MARK: - ხატულების წრე (.ic)

public enum CGIconStyle {
    case accent, ok, bad, inverted
}

public struct CGIcon: View {
    let systemName: String
    var style: CGIconStyle = .accent
    @Environment(\.colorScheme) private var scheme

    public init(_ systemName: String, style: CGIconStyle = .accent) {
        self.systemName = systemName
        self.style = style
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        Image(systemName: systemName)
            .font(.system(size: 17, weight: .medium))
            .foregroundStyle(iconColor(p))
            .frame(width: 38, height: 38)
            .background(Circle().fill(bgColor(p)))
    }

    private func iconColor(_ p: CGPalette) -> Color {
        switch style {
        case .accent: return CGColor_.accent
        case .ok: return CGColor_.ok
        case .bad: return CGColor_.bad
        case .inverted: return .white
        }
    }

    private func bgColor(_ p: CGPalette) -> Color {
        switch style {
        case .accent: return p.accentSoft
        case .ok: return CGColor_.ok.opacity(0.14)
        case .bad: return CGColor_.bad.opacity(0.13)
        case .inverted: return Color.white.opacity(0.22)
        }
    }
}

// MARK: - მწკრივი (.row) + გამყოფი

public struct CGRow: View {
    let icon: String
    var iconStyle: CGIconStyle
    let title: String
    var subtitle: String?
    var showsSeparator: Bool
    private let trailing: AnyView
    var action: (() -> Void)?

    @Environment(\.colorScheme) private var scheme

    /// მწკრივი: trailing closure არის toggle/ტექსტი, ან CGChevron() ნავიგაციური მწკრივისთვის.
    public init(icon: String,
                iconStyle: CGIconStyle = .accent,
                title: String,
                subtitle: String? = nil,
                showsSeparator: Bool = true,
                @ViewBuilder trailing: () -> some View,
                action: (() -> Void)? = nil) {
        self.icon = icon
        self.iconStyle = iconStyle
        self.title = title
        self.subtitle = subtitle
        self.showsSeparator = showsSeparator
        self.trailing = AnyView(trailing())
        self.action = action
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        Button {
            action?()
        } label: {
            HStack(spacing: 13) {
                CGIcon(icon, style: iconStyle)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(p.text)
                        .lineLimit(1)
                    if let subtitle, !subtitle.isEmpty {
                        Text(subtitle)
                            .font(.system(size: 12.5))
                            .foregroundColor(p.text2)
                            .lineLimit(1)
                    }
                }
                Spacer(minLength: 8)
                trailing
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(action == nil)
        .overlay(alignment: .top) {
            if showsSeparator {
                Rectangle()
                    .fill(p.separator)
                    .frame(height: 1)
                    .padding(.leading, 62)
                    .padding(.trailing, 16)
            }
        }
    }
}

public struct CGChevron: View {
    var value: String?
    @Environment(\.colorScheme) private var scheme
    public init(value: String? = nil) { self.value = value }
    public var body: some View {
        let p = CGPalette.scheme(scheme)
        HStack(spacing: 4) {
            if let value, !value.isEmpty {
                Text(value).font(.system(size: 13.5)).foregroundColor(p.text2)
            }
            Image(systemName: "chevron.right")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(p.text2)
        }
    }
}

// MARK: - გადამრთველი (.tg)

public struct CGToggle: View {
    @Binding var isOn: Bool
    @Environment(\.colorScheme) private var scheme

    public init(isOn: Binding<Bool>) { _isOn = isOn }

    public var body: some View {
        Button {
            withAnimation(.spring(response: 0.35, dampingFraction: 0.7)) { isOn.toggle() }
        } label: {
            ZStack(alignment: .leading) {
                Capsule()
                    .fill(isOn ? CGColor_.accent : Color.gray.opacity(scheme == .dark ? 0.45 : 0.35))
                    .frame(width: 52, height: 32)
                Circle()
                    .fill(Color.white)
                    .frame(width: 28, height: 28)
                    .shadow(color: .black.opacity(0.3), radius: 3, y: 2)
                    .offset(x: isOn ? 22 : 2)
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel(isOn ? "ჩართულია" : "გამორთულია")
    }
}

// MARK: - სეგმენტი (.sg)

public struct CGSegmented: View {
    let options: [(key: String, label: String)]
    @Binding var selection: String
    @Environment(\.colorScheme) private var scheme

    public init(options: [(String, String)], selection: Binding<String>) {
        self.options = options.map { (key: $0.0, label: $0.1) }
        _selection = selection
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        HStack(spacing: 0) {
            ForEach(options, id: \.key) { o in
                Button {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) { selection = o.key }
                } label: {
                    Text(o.label)
                        .font(.system(size: 13.5, weight: .semibold))
                        .foregroundColor(p.text)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background(
                            RoundedRectangle(cornerRadius: 11, style: .continuous)
                                .fill(selection == o.key ? p.card : .clear)
                                .shadow(color: .black.opacity(selection == o.key ? 0.12 : 0), radius: 4, y: 2))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(3)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(p.separator))
    }
}

// MARK: - ჭიქა-ნიშანი (.bg)

public enum CGBadgeStyle { case accent, ok, bad, off }

public struct CGBadge: View {
    let text: String
    var style: CGBadgeStyle = .accent
    @Environment(\.colorScheme) private var scheme

    public init(_ text: String, style: CGBadgeStyle = .accent) {
        self.text = text
        self.style = style
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        Text(text)
            .font(.system(size: 11.5, weight: .bold))
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(Capsule().fill(color(p).opacity(0.15)))
            .foregroundColor(color(p))
    }

    private func color(_ p: CGPalette) -> Color {
        switch style {
        case .accent: return CGColor_.accent
        case .ok: return CGColor_.ok
        case .bad: return CGColor_.bad
        case .off: return p.text2
        }
    }
}

// MARK: - ღილაკები (.btn)

public enum CGButtonStyle_ { case primary, secondary, danger, ok }

public struct CGButton: View {
    let title: String
    var systemImage: String?
    var style: CGButtonStyle_ = .primary
    var loading = false
    let action: () -> Void
    @Environment(\.colorScheme) private var scheme

    public init(_ title: String,
                systemImage: String? = nil,
                style: CGButtonStyle_ = .primary,
                loading: Bool = false,
                action: @escaping () -> Void) {
        self.title = title
        self.systemImage = systemImage
        self.style = style
        self.loading = loading
        self.action = action
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        Button {
            action()
        } label: {
            HStack(spacing: 8) {
                if loading {
                    ProgressView().tint(style == .primary ? .white : fg(p))
                } else if let systemImage {
                    Image(systemName: systemImage).font(.system(size: 14, weight: .bold))
                }
                Text(title).font(.system(size: 15, weight: .bold))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(bg(p)))
            .foregroundColor(fg(p))
            .shadow(color: shadow(p), radius: 12, y: 6)
        }
        .buttonStyle(.plain)
        .disabled(loading)
    }

    private func bg(_ p: CGPalette) -> Color {
        switch style {
        case .primary:
            return LinearGradient(colors: [CGColor_.accent, CGColor_.deep],
                                  startPoint: .topLeading, endPoint: .bottomTrailing).asColor()
        case .secondary: return p.accentSoft
        case .danger: return CGColor_.bad.opacity(0.12)
        case .ok: return CGColor_.ok.opacity(0.14)
        }
    }

    private func fg(_ p: CGPalette) -> Color {
        switch style {
        case .primary: return .white
        case .secondary: return CGColor_.accent
        case .danger: return CGColor_.bad
        case .ok: return CGColor_.ok
        }
    }

    private func shadow(_ p: CGPalette) -> Color {
        style == .primary ? CGColor_.accent.opacity(0.32) : .clear
    }
}

private extension LinearGradient {
    func asColor() -> Color { CGColor_.accent } // ჩრდილის გამოთვლა მარტივდება
}

public struct CGIconButton: View {
    let systemName: String
    let action: () -> Void
    @Environment(\.colorScheme) private var scheme

    public init(_ systemName: String, action: @escaping () -> Void) {
        self.systemName = systemName
        self.action = action
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        Button {
            action()
        } label: {
            Image(systemName: systemName)
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(CGColor_.accent)
                .frame(width: 54, height: 50)
                .background(
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .fill(LinearGradient(colors: [CGColor_.accent, CGColor_.deep],
                                             startPoint: .topLeading, endPoint: .bottomTrailing)))
                .foregroundColor(.white)
                .shadow(color: CGColor_.accent.opacity(0.32), radius: 12, y: 6)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - შესავალი ველი (input)

public struct CGInputStyle: ViewModifier {
    @Environment(\.colorScheme) private var scheme
    public func body(content: Content) -> some View {
        let p = CGPalette.scheme(scheme)
        content
            .padding(15)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(p.card))
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(p.cardBorder, lineWidth: 1))
            .foregroundColor(p.text)
    }
}

public extension View {
    func cgInput() -> some View { modifier(CGInputStyle()) }
}

// MARK: - ჭიპი (.chip)

public struct CGChip: View {
    let title: String
    let isOn: Bool
    let action: () -> Void
    @Environment(\.colorScheme) private var scheme

    public init(_ title: String, isOn: Bool, action: @escaping () -> Void) {
        self.title = title
        self.isOn = isOn
        self.action = action
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        Button(action: action) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(
                    Capsule()
                        .fill(isOn ? CGColor_.accent : p.card))
                .overlay(Capsule().stroke(isOn ? .clear : p.cardBorder, lineWidth: 1))
                .foregroundColor(isOn ? .white : p.text)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - არჩევანის წრე (.sel)

public struct CGSelector: View {
    let isOn: Bool
    @Environment(\.colorScheme) private var scheme

    public init(isOn: Bool) { self.isOn = isOn }

    public var body: some View {
        ZStack {
            Circle()
                .fill(isOn ? CGColor_.accent : .clear)
                .overlay(Circle().stroke(
                    isOn ? CGColor_.accent : CGPalette.scheme(scheme).separator,
                    lineWidth: 2))
            if isOn {
                Image(systemName: "checkmark")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
            }
        }
        .frame(width: 24, height: 24)
        .animation(.spring(response: 0.3, dampingFraction: 0.8), value: isOn)
    }
}

// MARK: - წყლის სფერო (.gl)

public struct WaterGlobe: View {
    let score: Int
    /// nil = ნაგულისხმევი ზომა; მცირე სიმაღლის (Landscape) ეკრანზე პატარა ზომა გადაეცემა.
    var size: CGFloat? = nil
    let action: () -> Void
    @Environment(\.colorScheme) private var scheme
    @State private var spin1 = false
    @State private var spin2 = false

    public init(score: Int, size: CGFloat? = nil, action: @escaping () -> Void) {
        self.score = score
        self.size = size
        self.action = action
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        Button(action: action) {
            ZStack {
                Circle()
                    .fill(p.card)
                    .overlay(Circle().stroke(p.cardBorder, lineWidth: 1.5))
                    .shadow(color: Color(red: 20 / 255, green: 70 / 255, blue: 160 / 255)
                        .opacity(scheme == .dark ? 0.35 : 0.09), radius: 15, y: 10)
                    .shadow(color: CGColor_.accent.opacity(0.12), radius: 20)

                GeometryReader { g in
                    let size = g.size.width
                    // დონე: score 100 → წყალი თითქმის ზედა წერტილამდე
                    let level = (100.0 - Double(score) * 0.92) / 100.0
                    WaterBlob(color: p.water, level: level, size: size, spinning: spin1, duration: 11)
                    WaterBlob(color: p.water2, level: level + 0.03, size: size, spinning: spin2, duration: 16)
                }

                VStack(spacing: 2) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 26, weight: .semibold))
                        .foregroundColor(CGColor_.accent)
                        .padding(.bottom, 4)
                    Text("\(score)%")
                        .font(.system(size: 50, weight: .heavy))
                        .foregroundColor(p.text)
                        .monospacedDigit()
                    Text("დაცვის დონე")
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundColor(p.text2)
                }
            }
            .frame(width: size ?? CGLayout.globeSize, height: size ?? CGLayout.globeSize)
        }
        .buttonStyle(.plain)
        .onAppear {
            spin1 = true
            spin2 = true
        }
        .animation(.linear(duration: 11).repeatForever(autoreverses: false), value: spin1)
    }
}

private struct WaterBlob: View {
    let color: Color
    let level: Double
    let size: Double
    let spinning: Bool
    let duration: Double

    var body: some View {
        Ellipse()
            .fill(color)
            .frame(width: size * 2.1, height: size * 2.1)
            .rotationEffect(.degrees(spinning ? 360 : 0))
            .offset(y: level * size + size * 1.05)
            .animation(.linear(duration: duration).repeatForever(autoreverses: false), value: spinning)
    }
}

// MARK: - სვეტებიანი დიაგრამა (.bars)

public struct CGBarsChart: View {
    let values: [Double]
    let labels: [String]
    /// nil = ნაგულისხმევი მაქსიმალური სიმაღლე; Landscape-ზე იკუმშება.
    var maxHeight: Double? = nil
    @Environment(\.colorScheme) private var scheme
    @State private var appeared = false

    public init(values: [Double], labels: [String], maxHeight: Double? = nil) {
        self.values = values
        self.labels = labels
        self.maxHeight = maxHeight
    }

    private func barFill(_ i: Int) -> AnyShapeStyle {
        if i == values.count - 1 {
            let grad = LinearGradient(colors: [CGColor_.accent2, CGColor_.accent],
                                      startPoint: .top, endPoint: .bottom)
            return AnyShapeStyle(grad)
        }
        return AnyShapeStyle(CGPalette.scheme(scheme).accentSoft)
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        let maxV = values.max() ?? 1
        HStack(alignment: .bottom, spacing: 7) {
            ForEach(values.indices, id: \.self) { i in
                VStack(spacing: 6) {
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(barFill(i))
                        .frame(maxHeight: .infinity)
                        .scaleEffect(y: appeared ? values[i] / maxV : 0.001, anchor: .bottom)
                    Text(labels[i])
                        .font(.system(size: 10.5))
                        .foregroundColor(p.text2)
                }
                .frame(maxWidth: .infinity)
            }
        }
        .frame(height: maxHeight ?? CGLayout.barsMaxHeight)
        .onAppear {
            withAnimation(.spring(response: 0.8, dampingFraction: 0.8)) { appeared = true }
        }
    }
}

// MARK: - დასტის ზოლი (.stk)

public struct CGStackBar: View {
    let segments: [(color: Color, fraction: Double)]
    @State private var appeared = false

    public init(segments: [(Color, Double)]) {
        self.segments = segments.map { (color: $0.0, fraction: $0.1) }
    }

    public var body: some View {
        HStack(spacing: 3) {
            ForEach(segments.indices, id: \.self) { i in
                RoundedRectangle(cornerRadius: 2)
                    .fill(segments[i].color)
                    .frame(width: appeared ? nil : 0)
                    .frame(maxWidth: appeared ? .infinity : 0)
            }
        }
        .frame(height: 14)
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        .onAppear {
            withAnimation(.spring(response: 0.9, dampingFraction: 0.9)) { appeared = true }
        }
    }
}

// MARK: - პროგრესის ზოლი (.mt)

public struct CGMeter: View {
    let fraction: Double
    @State private var appeared = false
    @Environment(\.colorScheme) private var scheme

    public init(fraction: Double) { self.fraction = fraction }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        GeometryReader { _ in
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 3).fill(p.separator)
                RoundedRectangle(cornerRadius: 3)
                    .fill(LinearGradient(colors: [CGColor_.accent, CGColor_.accent2],
                                         startPoint: .leading, endPoint: .trailing))
                    .frame(width: appeared ? nil : 0)
                    .frame(maxWidth: appeared ? .infinity : 0, alignment: .leading)
            }
        }
        .frame(height: 6)
        .onAppear {
            withAnimation(.spring(response: 0.9, dampingFraction: 0.9)) { appeared = true }
        }
    }
}

// MARK: - დოკი (.dock / .tab / .cb)

public struct CGDock: View {
    let activeTab: String
    let onSelect: (String) -> Void
    @Environment(\.colorScheme) private var scheme
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    public init(activeTab: String, onSelect: @escaping (String) -> Void) {
        self.activeTab = activeTab
        self.onSelect = onSelect
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        // ერთიანი დოკი ყველა ზომაზე: ვიწრო ეკრანზე (iPhone) კომპაქტური
        // ცენტრალური ღილაკით, რომ ლეიბლებს არ აკლდეს ადგილი; ფართო კლასზე — მცურავი.
        let isCompact = horizontalSizeClass == .compact
        HStack(spacing: 0) {
            dockTab("home", "მთავარი", "house")
            dockTab("stats", "სტატისტიკა", "chart.bar")
            centerButton
                .padding(.horizontal, isCompact ? 2 : 6)
            dockTab("filt", "ფილტრები", "line.3.horizontal.decrease")
            dockTab("more", "მეტი", "ellipsis")
        }
        .padding(.horizontal, isCompact ? 4 : 8)
        .frame(height: isCompact ? CGLayout.dockHeightCompact : CGLayout.dockHeight)
        .background(
            RoundedRectangle(cornerRadius: 34, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay(RoundedRectangle(cornerRadius: 34, style: .continuous).fill(p.dock))
                .overlay(RoundedRectangle(cornerRadius: 34, style: .continuous).stroke(p.cardBorder, lineWidth: 1)))
        .shadow(color: Color(red: 10 / 255, green: 40 / 255, blue: 100 / 255).opacity(0.25), radius: 20, y: 14)
        .padding(.horizontal, 16)
    }

    private func dockTab(_ key: String, _ label: String, _ icon: String) -> some View {
        let p = CGPalette.scheme(scheme)
        return Button {
            onSelect(key)
        } label: {
            VStack(spacing: 3) {
                Image(systemName: icon).font(.system(size: 19, weight: .medium))
                Text(label).font(.system(size: 10, weight: .semibold))
            }
            .foregroundColor(activeTab == key ? CGColor_.accent : p.text2)
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.plain)
    }

    private var centerButton: some View {
        let p = CGPalette.scheme(scheme)
        return Button {
            onSelect("prot")
        } label: {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: horizontalSizeClass == .compact ? 20 : 24, weight: .semibold))
                .foregroundColor(.white)
                .frame(width: horizontalSizeClass == .compact ? CGLayout.dockCenterSizeCompact : CGLayout.dockCenterSize,
                       height: horizontalSizeClass == .compact ? CGLayout.dockCenterSizeCompact : CGLayout.dockCenterSize)
                .background(Circle().fill(LinearGradient(colors: [CGColor_.accent2, CGColor_.deep],
                                                         startPoint: .topLeading, endPoint: .bottomTrailing)))
                .overlay(Circle().stroke(p.bg, lineWidth: 5))
                .shadow(color: CGColor_.accent.opacity(0.5), radius: 13, y: 6)
                .scaleEffect(activeTab == "prot" ? 1.05 : 1)
                .offset(y: activeTab == "prot" ? -3 : 0)
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 6)
    }
}

// MARK: - სათაურის ზოლი (.nb)

public struct CGNavBar: View {
    let title: String
    let compact: Bool
    let onBack: (() -> Void)?
    @Environment(\.colorScheme) private var scheme

    public init(title: String, compact: Bool, onBack: (() -> Void)? = nil) {
        self.title = title
        self.compact = compact
        self.onBack = onBack
    }

    public var body: some View {
        HStack(spacing: 10) { navContent }
            .padding(.horizontal, 22)
            .padding(.top, 16)
            .padding(.bottom, 10)
            .background(navGradient)
    }

    @ViewBuilder
    private var navContent: some View {
        let p = CGPalette.scheme(scheme)
        if compact {
            if let onBack {
                Button(action: onBack) {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundStyle(CGColor_.accent)
                        .frame(width: 40, height: 40)
                        .background(Circle().fill(.ultraThinMaterial))
                        .overlay(Circle().stroke(p.cardBorder, lineWidth: 1))
                }
                .buttonStyle(.plain)
            }
            Spacer()
            Text(title)
                .font(.system(size: 19, weight: .heavy))
                .foregroundColor(p.text)
            Spacer()
            Color.clear.frame(width: 40)
        } else {
            Text(title)
                .font(.system(size: 34, weight: .heavy))
                .tracking(-1)
                .foregroundColor(p.text)
            Spacer()
        }
    }

    private var navGradient: some View {
        let p = CGPalette.scheme(scheme)
        return LinearGradient(stops: [
            .init(color: p.bg, location: 0),
            .init(color: p.bg.opacity(0.55), location: 0.55),
            .init(color: .clear, location: 1)
        ], startPoint: .top, endPoint: .bottom)
        .ignoresSafeArea(edges: .top)
    }
}

// MARK: - სათაური h3

public struct CGSectionTitle: View {
    let text: String
    @Environment(\.colorScheme) private var scheme
    public init(_ text: String) { self.text = text }
    public var body: some View {
        Text(text)
            .font(.system(size: 13, weight: .bold))
            .tracking(0.3)
            .foregroundColor(CGPalette.scheme(scheme).text2)
            .padding(.leading, 6)
            .padding(.top, 22)
            .padding(.bottom, 9)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - „სატესტო მონაცემები“ ბანერი (.dm)

public struct CGTestDataBanner: View {
    var text = "სატესტო მონაცემები. რეალური სტატისტიკა გამოჩნდება დაცვის გამოყენების შემდეგ"
    @Environment(\.colorScheme) private var scheme
    public init(_ text: String? = nil) {
        if let text { self.text = text }
    }
    public var body: some View {
        let p = CGPalette.scheme(scheme)
        HStack(spacing: 8) {
            Image(systemName: "info.circle")
                .font(.system(size: 14, weight: .semibold))
            Text(text)
                .font(.system(size: 12.5, weight: .semibold))
                .fixedSize(horizontal: false, vertical: true)
        }
        .foregroundColor(CGColor_.accent)
        .padding(.horizontal, 13)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(p.accentSoft))
    }
}

// MARK: - ნაბიჯები (.stp)

public struct CGStepRow: View {
    let index: Int
    let text: String
    @Environment(\.colorScheme) private var scheme

    public init(index: Int, text: String) {
        self.index = index
        self.text = text
    }

    public var body: some View {
        let p = CGPalette.scheme(scheme)
        HStack(spacing: 13) {
            Text("\(index)")
                .font(.system(size: 13, weight: .bold))
                .foregroundColor(CGColor_.accent)
                .frame(width: 28, height: 28)
                .background(Circle().fill(p.accentSoft))
            Text(text)
                .font(.system(size: 14))
                .foregroundColor(p.text)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 13)
    }
}

// MARK: - ცარიელი მდგომარეობა (.em)

public struct CGEmpty: View {
    let text: String
    @Environment(\.colorScheme) private var scheme
    public init(_ text: String) { self.text = text }
    public var body: some View {
        Text(text)
            .font(.system(size: 14))
            .foregroundColor(CGPalette.scheme(scheme).text2)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 30)
    }
}

// MARK: - ლოგო (შენახულია წინა ვერსიიდან)

public struct CleanGEOLogo: View {
    public var size: CGFloat = 96
    public init(size: CGFloat = 96) { self.size = size }
    public var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.32, style: .continuous)
                .fill(LinearGradient(colors: [CGColor_.accent2, CGColor_.deep],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
                .shadow(color: CGColor_.accent.opacity(0.4), radius: size * 0.19, y: size * 0.18)
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: size * 0.55, weight: .semibold))
                .foregroundColor(.white)
        }
        .frame(width: size, height: size)
    }
}

// MARK: - სტატუსის ჭიკარტი (ძველი API)

public struct StatusPill: View {
    let text: String
    let color: Color
    public var body: some View {
        Text(text)
            .font(.system(size: 11.5, weight: .bold))
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundColor(color)
    }
}
