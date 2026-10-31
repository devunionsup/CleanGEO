//
//  BlockerRequestHandler.swift
//  CleanGEO BlockerExtension
//
//  Safari Content Blocker extension. Reads the compiled rule set that the
//  app publishes into the shared App Group container and returns it to
//  Safari. Re-read on each reload so filter updates apply immediately
//  without relaunching Safari.
//

import Foundation
import SafariServices

final class BlockerRequestHandler: NSObject, NSExtensionRequestHandling {

    private static let rulesFileName = "cleangeo-blocker.json"

    func beginRequest(with context: NSExtensionContext) {
        let rules = Self.loadRules()

        // Safari's hard limit.
        let limited = Array(rules.prefix(150_000))

        let item = NSExtensionItem()
        let json = (try? JSONEncoder().encode(limited)) ?? Data("[]".utf8)

        item.attachments = [
            NSItemProvider(item: json as NSData, typeIdentifier: UTType.json.identifier)
        ]
        context.completeRequest(returningItems: [item], completionHandler: nil)
    }

    static func loadRules() -> [DecodedRule] {
        let fm = FileManager.default
        let urls: [URL?] = [
            fm.containerURL(forSecurityApplicationGroupIdentifier: "group.87486bbbb00f533a.3")?
                .appendingPathComponent("Filters", isDirectory: true)
                .appendingPathComponent(rulesFileName),
            // Fallback for development without the App Group entitlement.
            fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
                .appendingPathComponent("Filters/working")
                .appendingPathComponent(rulesFileName)
        ]
        for url in urls {
            if let url, let data = try? Data(contentsOf: url),
               let rules = try? JSONDecoder().decode([DecodedRule].self, from: data) {
                return rules
            }
        }
        return []
    }
}

/// Mirror of CompiledRule for decoding without importing the app module.
struct DecodedRule: Codable {
    var trigger: Trigger
    var action: Action
    struct Trigger: Codable {
        var urlFilter: String?
        var ifDomain: [String]?
        var unlessDomain: [String]?
        var resourceTypes: [String]?
        var loadTypes: [String]?
        var loadContext: [String]?
        var ifTopURL: [String]?
        var unlessTopURL: [String]?
    }
    struct Action: Codable {
        var type: String
        var selector: String?
    }
}

import UniformTypeIdentifiers
