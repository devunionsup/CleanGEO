import Foundation

/// RFC 8484 DoH client (POST application/dns-message) with automatic fallback chain.
final class DoHClient {
    static let defaultChain = [
        "https://dns.adguard-dns.com/dns-query",
        "https://family.adguard-dns.com/dns-query"
    ]

    private let chain: [URL]
    private let session: URLSession
    private let lock = NSLock()
    private var active = 0

    var activeURL: URL { lock.lock(); defer { lock.unlock() }; return chain[active] }

    init(chain: [String] = DoHClient.defaultChain, timeout: TimeInterval = 4) {
        self.chain = chain.compactMap(URL.init(string:))
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout * 2
        cfg.waitsForConnectivity = false
        self.session = URLSession(configuration: cfg)
    }

    func resolve(_ query: Data, completion: @escaping (Data?) -> Void) {
        lock.lock(); let start = active; lock.unlock()
        attempt(query, offset: 0, start: start, completion: completion)
    }

    private func attempt(_ query: Data, offset: Int, start: Int, completion: @escaping (Data?) -> Void) {
        guard offset < chain.count else { return completion(nil) }
        let idx = (start + offset) % chain.count
        var req = URLRequest(url: chain[idx])
        req.httpMethod = "POST"
        req.httpBody = query
        req.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        req.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        session.dataTask(with: req) { [weak self] data, resp, err in
            guard let self = self else { return }
            if err == nil, let http = resp as? HTTPURLResponse, http.statusCode == 200,
               let data = data, data.count >= 12 {
                self.lock.lock(); self.active = idx; self.lock.unlock()   // remember working server
                completion(data)
            } else {
                self.attempt(query, offset: offset + 1, start: start, completion: completion)
            }
        }.resume()
    }

    /// Round-trip latency in ms, nil on failure (for the health indicator in the UI).
    static func probe(_ url: String, completion: @escaping (Int?) -> Void) {
        let c = DoHClient(chain: [url], timeout: 3)
        let t0 = Date()
        c.resolve(DNSWire.buildQuery(name: "example.com")) { d in
            completion(d == nil ? nil : Int(Date().timeIntervalSince(t0) * 1000))
        }
    }
}
