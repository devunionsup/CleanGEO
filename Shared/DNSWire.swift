import Foundation

/// Minimal DNS wire-format helpers (RFC 1035).
enum DNSWire {
    struct Question { let name: String; let type: UInt16; let end: Int }

    static func parseQuestion(_ d: Data) -> Question? {
        let b = [UInt8](d)
        guard b.count >= 12 else { return nil }
        let qd = Int(b[4]) << 8 | Int(b[5])
        guard qd >= 1 else { return nil }
        var i = 12
        var labels: [String] = []
        while true {
            guard i < b.count else { return nil }
            let len = Int(b[i]); i += 1
            if len == 0 { break }
            if len & 0xC0 != 0 { return nil }          // no compression in question
            guard i + len <= b.count else { return nil }
            labels.append(String(decoding: b[i..<i + len], as: UTF8.self).lowercased())
            i += len
        }
        guard i + 4 <= b.count else { return nil }
        let t = UInt16(b[i]) << 8 | UInt16(b[i + 1])
        return Question(name: labels.joined(separator: "."), type: t, end: i + 4)
    }

    /// Answer for a blocked name: A -> 0.0.0.0, AAAA -> ::, everything else NOERROR/empty.
    static func blockedResponse(for query: Data, q: Question) -> Data {
        var out = [UInt8](query.prefix(q.end))
        let rd = out[2] & 0x01
        out[2] = 0x80 | rd          // QR=1, opcode 0, RD echoed
        out[3] = 0x80               // RA=1, RCODE=0
        out[4] = 0; out[5] = 1      // QDCOUNT
        out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0
        var rdata: [UInt8] = []
        if q.type == 1 { rdata = [UInt8](repeating: 0, count: 4) }
        if q.type == 28 { rdata = [UInt8](repeating: 0, count: 16) }
        if rdata.isEmpty {
            out[6] = 0; out[7] = 0
        } else {
            out[6] = 0; out[7] = 1
            out += [0xC0, 0x0C, UInt8(q.type >> 8), UInt8(q.type & 0xFF), 0, 1, 0, 0, 0, 60,
                    0, UInt8(rdata.count)]
            out += rdata
        }
        return Data(out)
    }

    static func buildQuery(name: String, type: UInt16 = 1, id: UInt16 = UInt16.random(in: 0...UInt16.max)) -> Data {
        var b: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            let u = Array(label.utf8)
            b.append(UInt8(u.count)); b += u
        }
        b += [0, UInt8(type >> 8), UInt8(type & 0xFF), 0, 1]
        return Data(b)
    }
}
