import Foundation

/// AdGuard/ABP-style subset -> Safari content-blocker JSON + DNS domain list.
struct FilterCompiler {
    static let maxRules = 150_000

    struct Output { let json: Data; let domainList: String; let ruleCount: Int }

    static func compile(_ text: String) -> Output {
        var rules: [[String: Any]] = []
        var exceptions: [[String: Any]] = []
        var css: [String: [String]] = [:]
        var dns: [String] = []
        var seen = Set<String>()

        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("!") || line.hasPrefix("[") { continue }

            if let r = line.range(of: "##"), !line.hasPrefix("@@") {          // cosmetic
                let domains = String(line[..<r.lowerBound]).split(separator: ",").map(String.init)
                let sel = String(line[r.upperBound...])
                css[sel, default: []].append(contentsOf: domains)
                continue
            }
            var l = line, isException = false
            if l.hasPrefix("@@") { isException = true; l.removeFirst(2) }
            guard l.hasPrefix("||") else { continue }
            l.removeFirst(2)
            let optSplit = l.split(separator: "$", maxSplits: 1, omittingEmptySubsequences: false)
            var pattern = String(optSplit[0])
            guard pattern.hasSuffix("^") else { continue }
            pattern.removeLast()
            guard !pattern.isEmpty, !pattern.contains("*") else { continue }

            let hostOnly = !pattern.contains("/")
            let filter = "^https?://([^/]+\\.)?" + NSRegularExpression.escapedPattern(for: pattern)
            guard seen.insert((isException ? "@" : "") + filter).inserted else { continue }

            let trigger: [String: Any] = ["url-filter": filter]
            if isException {
                exceptions.append(["trigger": trigger, "action": ["type": "ignore-previous-rules"]])
                if hostOnly { dns.append("@\t\(pattern)") }
            } else {
                rules.append(["trigger": trigger, "action": ["type": "block"]])
                if hostOnly {
                    let cat = pattern.range(of: "track|analytic|metric|pixel|telemetry",
                                            options: .regularExpression) != nil ? "t" : "a"
                    dns.append("\(cat)\t\(pattern)")
                }
            }
        }
        for (sel, doms) in css {
            var trig: [String: Any] = ["url-filter": ".*"]
            if !doms.isEmpty { trig["if-domain"] = doms.map { "*" + $0 } }
            rules.append(["trigger": trig, "action": ["type": "css-display-none", "selector": sel]])
        }
        var all = rules + exceptions                       // exceptions last so they win
        if all.count > maxRules { all = Array(rules.prefix(maxRules - exceptions.count)) + exceptions }
        let json = (try? JSONSerialization.data(withJSONObject: all)) ?? Data("[]".utf8)
        return Output(json: json, domainList: dns.joined(separator: "\n"), ruleCount: all.count)
    }
}
