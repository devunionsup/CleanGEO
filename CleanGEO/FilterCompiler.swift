//
//  FilterCompiler.swift
//  CleanGEO
//
//  Compiles AdGuard-compatible filter text into Safari Content Blocker JSON.
//
//  Supported (subset that Safari's blocker can express):
//    - Network rules:  ||example.com^, |http://x|, @@||whitelist^, $important
//    - Modifier subset: $script, $image, $stylesheet, $xmlhttprequest,
//      $third-party, $first-party, $domain=..., $important
//    - Cosmetic rules: ##selector, #?#selector, #@$#selector (unhide)
//    - Comments, [AdGuard], !, #, and basic AdGuard HTML filtering directives
//      are ignored (Safari blocker has no HTML filtering).
//
//  Not supported by Safari's engine and therefore skipped:
//    - $redirect, $replace, $jsinject (scriptlets), $websocket, $csp,
//      $removeparam, $ghide, $dnstype, $dnsrewrite, $popup
//

import Foundation

/// One compiled Safari content-blocking rule.
public struct CompiledRule: Codable, Equatable {
    public var trigger: Trigger
    public var action: Action

    public struct Trigger: Codable, Equatable {
        public var urlFilter: String?
        public var ifDomain: [String]?
        public var unlessDomain: [String]?
        public var resourceTypes: [String]?
        public var loadTypes: [String]?
        public var loadContext: [String]?
        public var ifTopURL: [String]?
        public var unlessTopURL: [String]?

        enum CodingKeys: String, CodingKey {
            case urlFilter
            case ifDomain
            case unlessDomain
            case resourceTypes
            case loadTypes
            case loadContext
            case ifTopURL
            case unlessTopURL
        }
    }

    public struct Action: Codable, Equatable {
        public var type: String
        public var selector: String?

        enum CodingKeys: String, CodingKey {
            case type
            case selector
        }
    }
}

public enum FilterCompilerError: Error, LocalizedError {
    case emptyFilter
    case tooManyRules(Int)
    case malformedRule(String)

    public var errorDescription: String? {
        switch self {
        case .emptyFilter:
            return "ფილტრი ცარიელია"
        case .tooManyRules(let n):
            return "წესების რაოდენობა აღემატება ლიმიტს (\(n))"
        case .malformedRule(let r):
            return "არასწორი წესი: \(r)"
        }
    }
}

public final class FilterCompiler {

    /// Safari's documented hard limit.
    public static let safariRuleLimit = 150_000

    public init() {}

    // MARK: - Public API

    /// Compile a whole filter list (AdGuard syntax) into Safari JSON rules.
    /// Returns rules that survived conversion. Invalid lines are skipped.
    public func compile(text: String) throws -> [CompiledRule] {
        var out: [CompiledRule] = []
        out.reserveCapacity(4_096)

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty else { continue }

            if let rule = compileLine(line) {
                out.append(rule)
                if out.count > Self.safariRuleLimit {
                    throw FilterCompilerError.tooManyRules(Self.safariRuleLimit)
                }
            }
        }
        return out
    }

    /// Serialize compiled rules into the JSON Safari expects.
    public func toJSON(_ rules: [CompiledRule]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return try encoder.encode(rules)
    }

    // MARK: - Line-level conversion

    func compileLine(_ line: String) -> CompiledRule? {
        // Comments / metadata
        if line.hasPrefix("!") || line.hasPrefix("[") || line.hasPrefix("# ") {
            return nil
        }
        // AdGuard's AdGuard-specific scriptlet bodies and CSS injections
        // (#%#...) cannot run inside Safari's blocker.
        if line.contains("#%#") || line.contains("#$#") || line.contains("#$?") {
            return nil
        }
        // Extended CSS selectors (:has, :has-text...) work only partially; keep plain ones.
        if line.contains("##^") && line.contains("::") {
            return nil
        }

        // Cosmetic rules
        if let cosmetic = compileCosmetic(line) {
            return cosmetic
        }

        // Network rules
        return compileNetworkRule(line)
    }

    // MARK: Cosmetic

    private func compileCosmetic(_ line: String) -> CompiledRule? {
        // Unhide: domain##@#selector or #@$#selector
        if let idx = line.range(of: "#@$#") {
            let domains = parseDomainPrefix(String(line[line.startIndex..<idx.lowerBound]))
            let selector = String(line[idx.upperBound...])
            guard !selector.isEmpty else { return nil }
            var t = CompiledRule.Trigger(urlFilter: nil, ifDomain: domains.isEmpty ? nil : domains, unlessDomain: nil, resourceTypes: nil, loadTypes: nil, loadContext: nil, ifTopURL: nil, unlessTopURL: nil)
            return CompiledRule(trigger: t, action: .init(type: "ignore-previous-rules", selector: selector))
        }

        // Standard hide: ## or #?#
        for marker in ["#?#", "##"] {
            guard let idx = line.range(of: marker) else { continue }
            let domainPart = String(line[line.startIndex..<idx.lowerBound])
            var selector = String(line[idx.upperBound...])
            // Extended CSS is not supported by Safari's engine.
            if selector.contains(":has-text") || selector.contains(":matches-css") { return nil }
            guard isValidCSS(selector) else { return nil }

            var domains: [String] = []
            var exceptions: [String] = []
            for d in domainPart.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) {
                if d.hasPrefix("~") {
                    if d.count > 1 { exceptions.append(String(d.dropFirst())) }
                } else if !d.isEmpty {
                    domains.append(d)
                }
            }
            var t = CompiledRule.Trigger(urlFilter: nil, ifDomain: nil, unlessDomain: nil, resourceTypes: nil, loadTypes: nil, loadContext: nil, ifTopURL: nil, unlessTopURL: nil)
            t.ifDomain = domains.isEmpty ? nil : domains
            t.unlessDomain = exceptions.isEmpty ? nil : exceptions
            return CompiledRule(trigger: t, action: .init(type: "css-display-none", selector: selector))
        }
        return nil
    }

    private func isValidCSS(_ s: String) -> Bool {
        guard s.contains(".") || s.contains("#") || s.contains("[") || s.contains(">") ||
              s.contains("<") || s.contains(",") || s.contains(":") || s.contains(" ") else {
            return false
        }
        return true
    }

    /// Parse `example.com,~sub.example.org` in front of a cosmetic marker.
    private func parseDomainPrefix(_ s: String) -> [String] {
        guard !s.isEmpty else { return [] }
        return s.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    // MARK: Network rules

    private func compileNetworkRule(_ raw: String) -> CompiledRule? {
        var line = raw

        var isException = false
        if line.hasPrefix("@@") {
            isException = true
            line = String(line.dropFirst(2))
        }

        var important = false
        if line.contains("$important") {
            important = true
            line = line.replacingOccurrences(of: "$important", with: "")
        }

        // Split modifiers off the pattern.
        var modifiers: [String] = []
        if let dollar = line.range(of: "$") {
            let modPart = String(line[dollar.upperBound...])
            line = String(line[line.startIndex..<dollar.lowerBound])
            if !modPart.isEmpty {
                modifiers = modPart.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            }
        }

        // Drop rules with modifiers Safari cannot express.
        let unsupported = ["redirect", "replace", "jsinject", "websocket", "csp",
                           "removeparam", "ghide", "dnstype", "dnsrewrite", "popup",
                           "network", "doc", "other", "ping"]
        for m in modifiers where unsupported.contains(m) {
            return nil
        }

        guard !line.isEmpty else { return nil }

        // Anchor handling.
        var prefix = ""
        var suffix = ""
        if line.hasPrefix("||") {
            line = String(line.dropFirst(2))
            // Safari url-filter is regex; "||" means "start of host".
            prefix = "^[a-z-]+://([a-z0-9-]+\\.)*"
        } else if line.hasPrefix("|") {
            line = String(line.dropFirst(1))
            prefix = "^"
        }

        if line.hasSuffix("^|") {
            // "end of hostname" anchor: same practical meaning as ^ here.
            line = String(line.dropLast(2))
            suffix = "([/:?#]|$)"
        } else if line.hasSuffix("|") {
            line = String(line.dropLast(1))
            suffix = "$"
        } else if line.hasSuffix("^") {
            line = String(line.dropLast(1))
            suffix = "([/:?#]|$)"
        }

        let pattern = Self.regexEscape(line)
        let urlFilter = prefix + pattern + suffix

        var resourceTypes: [String]? = nil
        var loadTypes: [String]? = nil
        var loadContext: [String]? = nil
        var domains: [String]? = nil
        var exceptions: [String]? = nil
        var thirdParty: Bool? = nil

        for m in modifiers {
            switch m {
            case "script":          resourceTypes = append(resourceTypes, "script")
            case "image":           resourceTypes = append(resourceTypes, "image")
            case "stylesheet":      resourceTypes = append(resourceTypes, "style-sheet")
            case "xmlhttprequest", "xhr", "fetch": resourceTypes = append(resourceTypes, "raw")
            case "subdocument", "frame", "iframe": resourceTypes = append(resourceTypes, "document")
            case "font":            resourceTypes = append(resourceTypes, "font")
            case "media":           resourceTypes = append(resourceTypes, "media")
            case "object", "object-subrequest": resourceTypes = append(resourceTypes, "media")
            case "third-party":     thirdParty = true
            case "~third-party", "first-party": thirdParty = false
            case "popup":           resourceTypes = append(resourceTypes, "popup")
            case let v where v.hasPrefix("domain="):
                let val = String(v.dropFirst("domain=".count))
                for d in val.split(separator: "|").map({ $0.trimmingCharacters(in: .whitespaces) }) {
                    if d.hasPrefix("~") {
                        exceptions = append(exceptions, String(d.dropFirst()))
                    } else if !d.isEmpty {
                        domains = append(domains, d)
                    }
                }
            default:
                // Unknown modifier: skip rule to be safe.
                if !m.isEmpty && !Self.knownHarmless.contains(m) {
                    return nil
                }
            }
        }

        if thirdParty == true {
            loadContext = ["child"]
        } else if thirdParty == false {
            loadContext = ["top"]
        }

        // "popup" resource type combined with exceptions is meaningless; simplify.
        var t = CompiledRule.Trigger(urlFilter: urlFilter,
                                     ifDomain: domains,
                                     unlessDomain: exceptions,
                                     resourceTypes: resourceTypes,
                                     loadTypes: loadTypes,
                                     loadContext: loadContext,
                                     ifTopURL: nil,
                                     unlessTopURL: nil)
        let actionType = isException ? "ignore-previous-rules" : "block"
        _ = important
        return CompiledRule(trigger: t, action: .init(type: actionType, selector: nil))
    }

    private func append(_ list: [String]?, _ value: String) -> [String] {
        var l = list ?? []
        if !l.contains(value) { l.append(value) }
        return l
    }

    /// Characters that need escaping inside a Safari url-filter regex.
    /// AdGuard wildcards translate as: `*` -> `.*`; a separator anchor `^`
    /// inside the pattern becomes a separator character class.
    static func regexEscape(_ s: String) -> String {
        var out = ""
        for ch in s {
            switch ch {
            case ".", "?", "+", "(", ")", "[", "]", "{", "}", "|", "$", "\\":
                out.append("\\").append(ch)
            case "*":
                out.append(".*")
            case "^":
                out.append("[/:?&=]")
            default:
                out.append(ch)
            }
        }
        return out
    }

    static let knownHarmless: Set<String> = [
        "important", "match-case", "background", "document", "inline-font",
        "inline-script", "other", "webrtc", "app", "strict-third-party",
        "strict-first-party", "css", "ping", "empty", "mp4"
    ]
}
