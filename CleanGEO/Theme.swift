//
//  Theme.swift
//  CleanGEO
//
//  The visual identity of CleanGEO.
//
//  Brand concept: Georgia's mountains meet a clear sky — a deep midnight
//  blue that reads as "clean network", with a bright sky-teal accent and a
//  warm sunset coral for warnings/destructive actions. The wordmark pairs
//  Noto Sans Georgian with SF Pro.
//

import SwiftUI

public enum Theme {
    /// Primary accent: sky teal.
    public static let accent = Color(red: 0.05, green: 0.66, blue: 0.63)
    /// Deep background: midnight blue-black.
    public static let backgroundDeep = Color(red: 0.043, green: 0.063, blue: 0.106)
    /// Card surface.
    public static let surface = Color(red: 0.078, green: 0.106, blue: 0.157)
    /// Secondary surface.
    public static let surfaceHigh = Color(red: 0.114, green: 0.153, blue: 0.220)
    /// Text.
    public static let textPrimary = Color.white
    public static let textSecondary = Color.white.opacity(0.62)
    /// Status colors.
    public static let success = Color(red: 0.20, green: 0.78, blue: 0.35)
    public static let warning = Color(red: 0.98, green: 0.75, blue: 0.18)
    public static let danger = Color(red: 0.94, green: 0.33, blue: 0.31)

    /// The app gradient, used on the hero card and buttons.
    public static let heroGradient = LinearGradient(
        colors: [Color(red: 0.05, green: 0.66, blue: 0.63),
                 Color(red: 0.11, green: 0.42, blue: 0.80)],
        startPoint: .topLeading, endPoint: .bottomTrailing)

    public static let cardGradient = LinearGradient(
        colors: [surface, surfaceHigh],
        startPoint: .top, endPoint: .bottom)
}

// MARK: - Reusable styles

public struct CardBackground: ViewModifier {
    public func body(content: Content) -> some View {
        content
            .background(Theme.cardGradient)
            .cornerRadius(20)
            .shadow(color: .black.opacity(0.25), radius: 12, y: 6)
    }
}

public extension View {
    func cleangeoCard() -> some View { modifier(CardBackground()) }
}

// MARK: - Logo

/// CleanGEO logo: a shield formed by the Georgian letter "ც" with a
/// mountain silhouette, drawn fully in vector code so it scales losslessly.
public struct CleanGEOLogo: View {
    public var size: CGFloat = 96

    public init(size: CGFloat = 96) { self.size = size }

    public var body: some View {
        ZStack {
            // Shield
            ShieldShape()
                .fill(Theme.heroGradient)
            // Inner mountain cut
            Mountains()
                .fill(Color.black.opacity(0.18))
            // Georgian letter ც (Mkhedruli "tsi") as a stylized path —
            // simplified: circle with an open top-left.
            Circle()
                .trim(from: 0.05, to: 0.95)
                .stroke(Color.white, style: StrokeStyle(lineWidth: size * 0.075, lineCap: .round))
                .frame(width: size * 0.42, height: size * 0.42)
                .offset(y: size * 0.04)
        }
        .frame(width: size, height: size * 1.12)
    }

    struct ShieldShape: Shape {
        public func path(in rect: CGRect) -> Path {
            var p = Path()
            let w = rect.width, h = rect.height
            p.move(to: CGPoint(x: w * 0.5, y: 0))
            p.addLine(to: CGPoint(x: w * 0.94, y: h * 0.14))
            p.addLine(to: CGPoint(x: w * 0.94, y: h * 0.58))
            p.addCurve(to: CGPoint(x: w * 0.5, y: h),
                       control1: CGPoint(x: w * 0.94, y: h * 0.86),
                       control2: CGPoint(x: w * 0.78, y: h))
            p.addCurve(to: CGPoint(x: w * 0.06, y: h * 0.58),
                       control1: CGPoint(x: w * 0.22, y: h),
                       control2: CGPoint(x: w * 0.06, y: h * 0.86))
            p.addLine(to: CGPoint(x: w * 0.06, y: h * 0.14))
            p.closeSubpath()
            return p
        }
    }

    struct Mountains: Shape {
        public func path(in rect: CGRect) -> Path {
            var p = Path()
            p.move(to: CGPoint(x: rect.minX, y: rect.maxY))
            p.addLine(to: CGPoint(x: rect.width * 0.32, y: rect.height * 0.42))
            p.addLine(to: CGPoint(x: rect.width * 0.48, y: rect.height * 0.62))
            p.addLine(to: CGPoint(x: rect.width * 0.62, y: rect.height * 0.34))
            p.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
            p.closeSubpath()
            return p
        }
    }
}

// MARK: - Toggle switch (Georgian-friendly sizing)

public struct StatusPill: View {
    let text: String
    let color: Color
    public var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(color.opacity(0.18))
            .foregroundColor(color)
            .clipShape(Capsule())
    }
}
