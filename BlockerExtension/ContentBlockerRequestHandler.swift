import Foundation

final class ContentBlockerRequestHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let url = FileManager.default.fileExists(atPath: AppGroup.blockerJSON.path)
            ? AppGroup.blockerJSON : Bundle.main.url(forResource: "empty", withExtension: "json")
        guard let url = url, let att = NSItemProvider(contentsOf: url) else {
            context.completeRequest(returningItems: nil); return
        }
        let item = NSExtensionItem()
        item.attachments = [att]
        context.completeRequest(returningItems: [item])
    }
}
