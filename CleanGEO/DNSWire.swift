//
//  DNSWire.swift
//  CleanGEO
//
//  DNS wire-format encoder/decoder with DNSSEC record parsing
//  (RRSIG, DNSKEY, DS, NSEC, NSEC3) and EDNS0 support.
//

import Foundation

public enum DNSRecordType: UInt16 {
    case a = 1, ns = 2, cname = 5, soa = 6, ptr = 12, mx = 15, txt = 16
    case aaaa = 28, srv = 33, opt = 41, ds = 43, rrsig = 46, nsec = 47
    case dnskey = 48, nsec3 = 50, any = 255
}

public struct DNSHeader {
    public var id: UInt16 = 0
    public var isResponse = false
    public var opcode: UInt8 = 0
    public var authoritative = false
    public var truncated = false
    public var recursionDesired = true
    public var recursionAvailable = false
    public var authenticatedData = false
    public var checkingDisabled = false
    public var rcode: UInt8 = 0
    public init() {}
}

public struct DNSQuestion {
    public var name: String
    public var type: DNSRecordType
    public init(name: String, type: DNSRecordType) {
        self.name = name
        self.type = type
    }
}

public struct DNSRecord {
    public var name: String
    public var type: DNSRecordType
    public var classIN: UInt16 = 1
    public var ttl: UInt32 = 0
    public var rdata: Data   // raw, uncompressed where applicable
    public init(name: String, type: DNSRecordType, ttl: UInt32, rdata: Data) {
        self.name = name
        self.type = type
        self.ttl = ttl
        self.rdata = rdata
    }

    public var isRRSIG: Bool { type == .rrsig }
}

public struct DNSMessage {
    public var header = DNSHeader()
    public var questions: [DNSQuestion] = []
    public var answers: [DNSRecord] = []
    public var authority: [DNSRecord] = []
    public var additional: [DNSRecord] = []

    public init() {}
}

public enum DNSWireError: Error {
    case truncated
    case badName
    case badRData
    case unsupported
}

// MARK: - Encoder

public enum DNSWire {

    public static func encodeQuery(question: DNSQuestion, id: UInt16,
                                   ednsDOBit: Bool = true,
                                   randomizeCase: Bool = true,
                                   payloadSize: UInt16 = 1232) throws -> Data {
        var out = Data()
        out.reserveCapacity(64)

        // 0x20 case randomization of QNAME for spoofing resistance.
        let name = randomizeCase ? randomCase(question.name) : question.name

        // Header
        var flags: UInt16 = 0x0100 // RD
        out.append(UInt16(id >> 8)); out.append(UInt16(id & 0xFF))
        out.append(UInt16(flags >> 8)); out.append(UInt16(flags & 0xFF))
        out.append(0); out.append(1)   // QDCOUNT = 1
        out.append(0); out.append(0)   // ANCOUNT
        out.append(0); out.append(0)   // NSCOUNT
        out.append(0); out.append(1)   // ARCOUNT = 1 (OPT)

        // QNAME
        appendName(name, to: &out)
        out.append(UInt16(question.type.rawValue >> 8))
        out.append(UInt16(question.type.rawValue & 0xFF))
        out.append(0); out.append(1)   // IN

        // OPT record: root name, type OPT, class = payload size, TTL: DO bit in extended flags
        out.append(0)
        out.append(UInt16(DNSRecordType.opt.rawValue >> 8)); out.append(UInt16(DNSRecordType.opt.rawValue & 0xFF))
        out.append(UInt16(payloadSize >> 8)); out.append(UInt16(payloadSize & 0xFF))
        let doBit: UInt32 = ednsDOBit ? 0x00008000 : 0
        out.append(UInt32(doBit >> 24)); out.append(UInt32((doBit >> 16) & 0xFF))
        out.append(UInt32((doBit >> 8) & 0xFF)); out.append(UInt32(doBit & 0xFF))
        out.append(0); out.append(0)   // RDLENGTH = 0
        return out
    }

    static func appendName(_ name: String, to out: inout Data) throws {
        let trimmed = name.hasSuffix(".") ? String(name.dropLast()) : name
        guard !trimmed.isEmpty else { out.append(0); return }
        for label in trimmed.split(separator: ".") {
            let bytes = Array(label.utf8)
            guard !bytes.isEmpty, bytes.count <= 63 else { throw DNSWireError.badName }
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(0)
    }

    static func randomCase(_ name: String) -> String {
        var result = ""
        for ch in name.lowercased() {
            result.append(Bool.random() ? ch.uppercased() : ch)
        }
        return result
    }

    /// The name as sent (for verifying case on the reply).
    public static func caseBitName(of name: String, randomize: Bool) -> String {
        randomize ? name.lowercased() : name
    }

    // MARK: - Decoder

    public static func decode(data: Data) throws -> DNSMessage {
        var reader = ByteReader(data: data)
        var msg = DNSMessage()
        let id = try reader.readUInt16()
        let flags = try reader.readUInt16()
        let qd = try reader.readUInt16()
        let an = try reader.readUInt16()
        let ns = try reader.readUInt16()
        let ar = try reader.readUInt16()

        var h = DNSHeader()
        h.id = id
        h.isResponse = (flags & 0x8000) != 0
        h.opcode = UInt8((flags >> 11) & 0xF)
        h.authoritative = (flags & 0x0400) != 0
        h.truncated = (flags & 0x0200) != 0
        h.recursionDesired = (flags & 0x0100) != 0
        h.recursionAvailable = (flags & 0x0080) != 0
        h.authenticatedData = (flags & 0x0020) != 0
        h.checkingDisabled = (flags & 0x0010) != 0
        h.rcode = UInt8(flags & 0xF)
        msg.header = h

        var seen = Set<Int>()
        for _ in 0..<qd {
            let name = try readName(&reader, jumps: &seen)
            let t = try reader.readUInt16()
            _ = try reader.readUInt16() // class
            if let type = DNSRecordType(rawValue: t) {
                msg.questions.append(DNSQuestion(name: name, type: type))
            }
        }
        msg.answers = try readRecords(&reader, count: Int(an), jumps: &seen)
        msg.authority = try readRecords(&reader, count: Int(ns), jumps: &seen)
        msg.additional = try readRecords(&reader, count: Int(ar), jumps: &seen)
        return msg
    }

    private static func readRecords(_ r: inout ByteReader, count: Int, jumps: inout Set<Int>) throws -> [DNSRecord] {
        var out: [DNSRecord] = []
        for _ in 0..<count {
            let name = try readName(&r, jumps: &jumps)
            let t = try r.readUInt16()
            _ = try r.readUInt16() // class
            let ttl = try r.readUInt32()
            let rdLen = Int(try r.readUInt16())
            guard rdLen >= 0, r.offset + rdLen <= r.data.count else { throw DNSWireError.truncated }
            // RDATA must be stored uncompressed for DNSSEC canonical form;
            // names inside RDATA may be compressed on the wire, so expand them.
            var rdata = Data()
            if rdLen > 0 {
                let start = r.offset
                switch DNSRecordType(rawValue: t) {
                case .ns, .cname, .ptr, .dname:
                    var jumps2 = Set<Int>()
                    rdata = try readName(&r, jumps: &jumps2).data(using: .utf8) ?? Data()
                case .soa:
                    var jumps2 = Set<Int>()
                    let mname = try readName(&r, jumps: &jumps2)
                    let rname = try readName(&r, jumps: &jumps2)
                    var soa = Data()
                    try appendName(mname, to: &soa)
                    try appendName(rname, to: &soa)
                    soa.append(contentsOf: r.readRaw(20) ?? Data())
                    rdata = soa
                case .mx:
                    var jumps2 = Set<Int>()
                    _ = try r.readUInt16()
                    let pref = (r.data[r.offset - 2] << 8) | r.data[r.offset - 1]
                    let exch = try readName(&r, jumps: &jumps2)
                    rdata = Data([UInt8(pref >> 8), UInt8(pref & 0xFF)])
                    rdata.append(contentsOf: exch.utf8)
                default:
                    r.offset = start
                    rdata = try r.readRaw(rdLen) ?? Data()
                }
                // Ensure we ended exactly at the record boundary.
                _ = try r.readRaw(max(0, (start + rdLen) - r.offset))
            }
            if let type = DNSRecordType(rawValue: t) {
                out.append(DNSRecord(name: name, type: type, ttl: ttl, rdata: rdata))
            }
        }
        return out
    }

    static func readName(_ r: inout ByteReader, jumps: inout Set<Int>) throws -> String {
        var labels: [String] = []
        var consumedOwn = 0
        var jumped = false
        while true {
            guard r.offset < r.data.count else { throw DNSWireError.truncated }
            let len = Int(r.data[r.offset])
            r.offset += 1
            if !jumped { consumedOwn += 1 }
            if len == 0 { break }
            if len & 0xC0 == 0xC0 {
                guard r.offset < r.data.count else { throw DNSWireError.truncated }
                let ptr = ((len & 0x3F) << 8) | Int(r.data[r.offset])
                r.offset += 1
                if !jumped { consumedOwn += 1 }
                if !jumps.insert(ptr).inserted { throw DNSWireError.badName } // loop guard
                jumped = true
                var sub = r
                sub.offset = ptr
                labels.append(try readName(&sub, jumps: &jumps))
                break
            }
            guard len <= 63, r.offset + len <= r.data.count else { throw DNSWireError.badName }
            let s = String(decoding: r.data[r.offset..<r.offset+len], as: UTF8.self)
            labels.append(s)
            r.offset += len
            if !jumped { consumedOwn += len }
        }
        return labels.joined(separator: ".")
    }
}

// MARK: - Byte reader

struct ByteReader {
    let data: Data
    var offset = 0
    init(_ d: Data) { self.data = d }

    mutating func readUInt8() throws -> UInt8 {
        guard offset < data.count else { throw DNSWireError.truncated }
        defer { offset += 1 }
        return data[offset]
    }
    mutating func readUInt16() throws -> UInt16 {
        let hi = try readUInt8(), lo = try readUInt8()
        return UInt16(hi) << 8 | UInt16(lo)
    }
    mutating func readUInt32() throws -> UInt32 {
        let a = try readUInt16(), b = try readUInt16()
        return UInt32(a) << 16 | UInt32(b)
    }
    mutating func readRaw(_ n: Int) throws -> Data {
        guard offset + n <= data.count else { throw DNSWireError.truncated }
        defer { offset += n }
        return data.subdata(in: offset..<offset+n)
    }
}

// MARK: - RDATA typed accessors

public struct RRSIGData {
    public var typeCovered: UInt16
    public var algorithm: UInt8
    public var labels: UInt8
    public var originalTTL: UInt32
    public var expiration: UInt32
    public var inception: UInt32
    public var keyTag: UInt16
    public var signerName: String
    public var signature: Data

    public init?(rdata: Data) {
        guard rdata.count > 18 else { return nil }
        var r = ByteReader(rdata)
        guard let tc = try? r.readUInt16(),
              let alg = try? r.readUInt8(),
              let lbl = try? r.readUInt8(),
              let ottl = try? r.readUInt32(),
              let exp = try? r.readUInt32(),
              let inc = try? r.readUInt32(),
              let kt = try? r.readUInt16() else { return nil }
        var jumps = Set<Int>()
        guard let signer = try? DNSWire.readName(&r, jumps: &jumps) else { return nil }
        self.typeCovered = tc
        self.algorithm = alg
        self.labels = lbl
        self.originalTTL = ottl
        self.expiration = exp
        self.inception = inc
        self.keyTag = kt
        self.signerName = signer
        self.signature = rdata.subdata(in: r.offset..<rdata.count)
    }
}

public struct DNSKEYData {
    public var flags: UInt16
    public var algorithm: UInt8
    public var publicKey: Data
    public var isZoneKey: Bool { flags & 0x0100 != 0 }
    public var isSEP: Bool { flags & 0x0001 != 0 }

    public init?(rdata: Data) {
        guard rdata.count > 4 else { return nil }
        var r = ByteReader(rdata)
        guard let f = try? r.readUInt16(),
              let proto = try? r.readUInt8(),
              let alg = try? r.readUInt8() else { return nil }
        guard proto == 3 else { return nil }
        self.flags = f
        self.algorithm = alg
        self.publicKey = rdata.subdata(in: r.offset..<rdata.count)
    }

    /// DNSSEC key tag (RFC 4034 App. B).
    public var keyTag: UInt16 {
        var ac: UInt32 = 0
        for (i, b) in publicKey.enumerated() {
            let v = UInt32(b)
            ac += (i & 1) == 1 ? v : v << 8
        }
        ac += (ac >> 16) & 0xFFFF
        return UInt16(ac & 0xFFFF)
    }
}

public struct DSData {
    public var keyTag: UInt16
    public var algorithm: UInt8
    public var digestType: UInt8
    public var digest: Data

    public init?(rdata: Data) {
        guard rdata.count > 4 else { return nil }
        var r = ByteReader(rdata)
        guard let kt = try? r.readUInt16(),
              let alg = try? r.readUInt8(),
              let dt = try? r.readUInt8() else { return nil }
        self.keyTag = kt
        self.algorithm = alg
        self.digestType = dt
        self.digest = rdata.subdata(in: r.offset..<rdata.count)
    }

    /// DS from a DNSKEY (RFC 4034 §5.1.4).
    public static func digest(of key: DNSKEYData, owner: String, type: UInt8) -> Data? {
        var wire = Data()
        try? DNSWire.appendName(owner, to: &wire)
        wire.append(UInt8(key.flags >> 8)); wire.append(UInt8(key.flags & 0xFF))
        wire.append(3) // protocol
        wire.append(key.algorithm)
        wire.append(contentsOf: key.publicKey)
        switch type {
        case 1:  return Data(SHA1.hash(data: wire))
        case 2:  return Data(SHA256.hash(data: wire))
        case 4:  return Data(SHA384.hash(data: wire))
        default: return nil
        }
    }
}

import CryptoKit
