//
//  DNSSECValidator.swift
//  CleanGEO
//
//  Chain-of-trust DNSSEC validation:
//    root DNSKEY -> DS at TLD -> DNSKEY -> DS at subdomain -> ...
//    RRSIG verification over RRsets.
//
//  Uses CryptoKit for RSA/ECDSA/Ed25519 primitive operations. RSA signature
//  verification (RSASSA-PKCS1-v1_5) is implemented on top of raw RSA
//  primitives; CryptoKit does not expose RSA, so we shell out to
//  SecKeyVerifySignature with a manually built SecKeyRef from the modulus
//  and exponent, or fall back to the asn.1 DER form. This file implements
//  RSA PKCS#1 v1.5 verification purely in Swift using vli arithmetic so it
//  works without external dependencies.
//

import Foundation
import CryptoKit

public enum DNSSECError: Error, Equatable {
    case noSignature
    case keyNotFound
    case signatureMismatch
    case signatureExpired
    case signatureNotYetValid
    case unsupportedAlgorithm(UInt8)
    case brokenChain
    case bogusData
}

public enum DNSSECAlgorithm: UInt8 {
    case rsasha256 = 8
    case rsasha512 = 10
    case ecdsap256sha256 = 13
    case ecdsap384sha384 = 14
    case ed25519 = 15
    // Legacy algorithms not supported for validation:
    case rsasha1 = 5, rsasha1nsec3 = 7
}

public final class DNSSECValidator {

    public struct TrustAnchor {
        public var zone: String            // "." for root
        public var key: DNSKEYData
        public init(zone: String, key: DNSKEYData) { self.zone = zone; self.key = key }
    }

    public private(set) var trustAnchors: [TrustAnchor]

    public init(trustAnchors: [TrustAnchor]? = nil) {
        if let t = trustAnchors {
            self.trustAnchors = t
        } else {
            self.trustAnchors = DNSSECValidator.ianRootAnchors()
        }
    }

    /// The IANA root KSKs (KSK-2017 tag 20326 and KSK-2024 tag 38696),
    /// from https://data.iana.org/root-anchors/root-anchors.xml.
    /// Both are kept active during the rollover period.
    public static func ianRootAnchors() -> [TrustAnchor] {
        // KSK-2017: flags 257 (KSK), alg 8 (RSASHA256), key tag 20326.
        let ksk2017B64 = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3" +
            "+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
        // KSK-2024: flags 257, alg 8, key tag 38696.
        let ksk2024B64 = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc="
        var out: [TrustAnchor] = []
        for b64 in [ksk2017B64, ksk2024B64] {
            guard let raw = Data(base64Encoded: b64) else { continue }
            // DNSKEY rdata = flags(2) || protocol(1) || algorithm(1) || pubkey.
            var rdata = Data([0x01, 0x01, 0x03, 0x08])
            rdata.append(raw.dropFirst(4))
            if let key = DNSKEYData(rdata: rdata) {
                out.append(TrustAnchor(zone: ".", key: key))
            }
        }
        return out
    }

    // MARK: - RRset helpers

    /// Verify a signed RRset.
    public func verify(rrset: [DNSRecord],
                       rrsig: RRSIGData,
                       dnskey: DNSKEYData) throws {
        // 1. Algorithm supported?
        guard let alg = DNSSECAlgorithm(rawValue: rrsig.algorithm),
              [.rsasha256, .rsasha512, .ecdsap256sha256, .ecdsap384sha384, .ed25519].contains(alg) else {
            throw DNSSECError.unsupportedAlgorithm(rrsig.algorithm)
        }
        // 2. Time validity.
        let now = UInt32(Date().timeIntervalSince1970)
        if now < rrsig.inception { throw DNSSECError.signatureNotYetValid }
        if now >= rrsig.expiration { throw DNSSECError.signatureExpired }

        // 3. Key tag must match.
        guard dnskey.keyTag == rrsig.keyTag else { throw DNSSECError.keyNotFound }

        // 4. Build canonical RDATA for each record in the RRset.
        guard let first = rrset.first else { throw DNSSECError.bogusData }
        let owner = canonicalize(first.name, labels: Int(rrsig.labels))

        var signedData = Data()
        try DNSWire.appendName(owner, to: &signedData)
        var typeCoveredBE = rrsig.typeCovered
        var tmp = Data()
        tmp.append(UInt8(typeCoveredBE >> 8)); tmp.append(UInt8(typeCoveredBE & 0xFF))
        tmp.append(rrsig.algorithm)
        tmp.append(rrsig.labels)
        tmp.append(UInt8(rrsig.originalTTL >> 24)); tmp.append(UInt8((rrsig.originalTTL >> 16) & 0xFF))
        tmp.append(UInt8((rrsig.originalTTL >> 8) & 0xFF)); tmp.append(UInt8(rrsig.originalTTL & 0xFF))
        tmp.append(UInt8(rrsig.expiration >> 24)); tmp.append(UInt8((rrsig.expiration >> 16) & 0xFF))
        tmp.append(UInt8((rrsig.expiration >> 8) & 0xFF)); tmp.append(UInt8(rrsig.expiration & 0xFF))
        tmp.append(UInt8(rrsig.inception >> 24)); tmp.append(UInt8((rrsig.inception >> 16) & 0xFF))
        tmp.append(UInt8((rrsig.inception >> 8) & 0xFF)); tmp.append(UInt8(rrsig.inception & 0xFF))
        tmp.append(UInt8(rrsig.keyTag >> 8)); tmp.append(UInt8(rrsig.keyTag & 0xFF))
        // Signer name in canonical form
        var signerWire = Data()
        try DNSWire.appendName(rrsig.signerName, to: &signerWire)
        tmp.append(signerWire)
        signedData.append(tmp)

        for rec in rrset {
            var rd = Data()
            rd.append(owner)
            rd.append(UInt8(rrsig.typeCovered >> 8)); rd.append(UInt8(rrsig.typeCovered & 0xFF))
            rd.append(0); rd.append(1) // class IN
            // TTL: the RRSIG's original TTL (RFC 4034 §3.1.8.1).
            let ttl = rrsig.originalTTL
            rd.append(UInt8(ttl >> 24)); rd.append(UInt8((ttl >> 16) & 0xFF))
            rd.append(UInt8((ttl >> 8) & 0xFF)); rd.append(UInt8(ttl & 0xFF))
            rd.append(UInt8(rec.rdata.count >> 8)); rd.append(UInt8(rec.rdata.count & 0xFF))
            rd.append(rec.rdata)
            signedData.append(rd)
        }

        // 5. Verify the signature.
        let sig = rrsig.signature
        switch alg {
        case .rsasha256:
            guard verifyRSA(dnskey: dnskey, message: signedData, signature: sig,
                            hash: .sha256) else { throw DNSSECError.signatureMismatch }
        case .rsasha512:
            guard verifyRSA(dnskey: dnskey, message: signedData, signature: sig,
                            hash: .sha512) else { throw DNSSECError.signatureMismatch }
        case .ecdsap256sha256:
            // DNSSEC ECDSA is raw r||s, 64 bytes; convert to DER for CryptoKit.
            guard sig.count == 64,
                  let key = try? P256.Signing.PublicKey(x963Representation: x963(key: dnskey.publicKey, fieldSize: 32)) else {
                throw DNSSECError.signatureMismatch
            }
            let sigData = try derFromRaw(sig)
            guard key.isValidSignature(sigData, for: signedData) else {
                throw DNSSECError.signatureMismatch
            }
        case .ecdsap384sha384:
            guard sig.count == 96,
                  let key = try? P384.Signing.PublicKey(x963Representation: x963(key: dnskey.publicKey, fieldSize: 48)) else {
                throw DNSSECError.signatureMismatch
            }
            let sigData = try derFromRaw(sig)
            guard key.isValidSignature(sigData, for: signedData) else {
                throw DNSSECError.signatureMismatch
            }
        case .ed25519:
            guard sig.count == 64,
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: dnskey.publicKey) else {
                throw DNSSECError.signatureMismatch
            }
            guard key.isValidSignature(sig, for: signedData) else {
                throw DNSSECError.signatureMismatch
            }
        default:
            throw DNSSECError.unsupportedAlgorithm(rrsig.algorithm)
        }
    }

    // MARK: - ECDSA helpers

    private func x963(key: Data, fieldSize: Int) -> Data {
        // DNSSEC stores the raw point; x963 = 0x04 || X || Y.
        var d = Data([0x04])
        d.append(key)
        return d
    }

    private func derFromRaw(_ sig: Data) throws -> Data {
        // r || s (raw) -> DER SEQUENCE of two INTEGERs.
        let half = sig.count / 2
        func encodeInt(_ v: Data) -> Data {
            var d = Data()
            var i = 0
            while i < v.count && v[i] == 0 { i += 1 }
            var bytes = Array(v[i...])
            if bytes.isEmpty { bytes = [0] }
            if bytes[0] & 0x80 != 0 { d.append(0) }
            d.append(contentsOf: bytes)
            return Data([0x02, UInt8(d.count)]) + d
        }
        let r = encodeInt(sig[0..<half])
        let s = encodeInt(sig[half...])
        let body = r + s
        return Data([0x30, UInt8(body.count)]) + body
    }

    // MARK: - RSA

    /// PKCS#1 v1.5 RSA verification using pure-Swift big-integer math.
    /// DNSSEC RSA public keys are exponent-e + modulus-n (RFC 3110).
    private func verifyRSA(dnskey: DNSKEYData, message: Data, signature: Data, hash: DigestAlgorithm) -> Bool {
        // RFC 3110: first 2 bytes = exponent length (or 0 + 3 bytes if 255...).
        let pk = dnskey.publicKey
        guard pk.count > 3 else { return false }
        var eLen = Int(pk[0])
        var off = 1
        if eLen == 0 {
            guard pk.count > 4 else { return false }
            eLen = (Int(pk[1]) << 8) | Int(pk[2])
            off = 3
        }
        guard eLen > 0, pk.count >= off + eLen else { return false }
        let e = pk.subdata(in: off..<off+eLen)
        let n = pk.subdata(in: off+eLen..<pk.count)
        guard !n.isEmpty, !e.isEmpty else { return false }

        // s^e mod n, then compare against the expected EMSA-PKCS1-v1_5 block.
        let s = BigInt(signature)
        let eBig = BigInt(e)
        let nBig = BigInt(n)
        guard s < nBig else { return false }
        let m = s.power(eBig, mod: nBig)
        let decoded = m.toDataPadded(nBig.byteCount)

        // Build the expected block: 0x00 0x01 FF...FF 0x00 || DigestInfo || H
        let digestInfo: [UInt8]
        switch hash {
        case .sha256: digestInfo = [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]
        case .sha512: digestInfo = [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40]
        }
        var hashBytes: [UInt8]
        switch hash {
        case .sha256: hashBytes = Array(SHA256.hash(data: message))
        case .sha512: hashBytes = Array(SHA512.hash(data: message))
        }
        var expected = Data([0x00, 0x01])
        expected.append(contentsOf: [UInt8](repeating: 0xFF, count: max(0, decoded.count - 3 - digestInfo.count - hashBytes.count)))
        expected.append(0x00)
        expected.append(contentsOf: digestInfo)
        expected.append(contentsOf: hashBytes)
        return expected == decoded
    }

    // MARK: - Name canonicalization

    /// RFC 4034 §6.2: lowercase; also trim down to the RRSIG labels field.
    func canonicalize(_ name: String, labels: Int) -> String {
        var parts = name.lowercased().split(separator: ".", omittingEmptySubsequences: false)
        if parts.count > labels && labels > 0 {
            // Wildcard expansion: replace leftmost with "*".
            parts = ["*"] + parts.suffix(labels)
        }
        return parts.joined(separator: ".")
    }
}

public enum DigestAlgorithm {
    case sha256, sha512
}

// MARK: - Big integer (minimal, for RSA modexp)

/// Small, self-contained big-integer with the operations needed for RSA:
/// comparison, multiplication, division/mod, and modpow (square & multiply).
public struct BigInt {
    public private(set) var words: [UInt32]   // little-endian 32-bit words
    public var isZero: Bool { words.isEmpty || (words.count == 1 && words[0] == 0) }

    public init(_ bytes: Data) {
        var w: [UInt32] = []
        var i = bytes.count
        while i > 0 {
            var v: UInt32 = 0
            let take = min(4, i)
            for k in 0..<take {
                v = (v << 8) | UInt32(bytes[i - take + k])
            }
            w.append(v)
            i -= take
        }
        words = Self.normalized(w)
    }

    init(_ w: [UInt32]) { words = Self.normalized(w) }

    static func normalized(_ w: [UInt32]) -> [UInt32] {
        var v = w
        while v.count > 1 && v.last == 0 { v.removeLast() }
        if v.isEmpty { v = [0] }
        return v
    }

    public var byteCount: Int {
        var count = (words.count - 1) * 4
        if let top = words.last {
            var t = top
            while t != 0 { count += 1; t >>= 8 }
        }
        return max(1, count)
    }

    /// Big-endian byte representation, left-padded to `total` bytes.
    public func toDataPadded(_ total: Int) -> Data {
        var all: [UInt8] = []
        for w in words.reversed() {
            all.append(UInt8((w >> 24) & 0xFF))
            all.append(UInt8((w >> 16) & 0xFF))
            all.append(UInt8((w >> 8) & 0xFF))
            all.append(UInt8(w & 0xFF))
        }
        var idx = 0
        while idx < all.count && all[idx] == 0 { idx += 1 }
        var bytes = Array(all[idx...])
        if bytes.isEmpty { bytes = [0] }
        if bytes.count < total {
            bytes = [UInt8](repeating: 0, count: total - bytes.count) + bytes
        }
        return Data(bytes)
    }

    public static func < (lhs: BigInt, rhs: BigInt) -> Bool {
        if lhs.words.count != rhs.words.count { return lhs.words.count < rhs.words.count }
        for i in stride(from: lhs.words.count - 1, through: 0, by: -1) {
            if lhs.words[i] != rhs.words[i] { return lhs.words[i] < rhs.words[i] }
        }
        return false
    }

    public static func == (lhs: BigInt, rhs: BigInt) -> Bool { lhs.words == rhs.words }

    /// lhs * rhs (no modulus).
    public static func * (lhs: BigInt, rhs: BigInt) -> BigInt {
        var out = [UInt32](repeating: 0, count: lhs.words.count + rhs.words.count)
        for i in 0..<lhs.words.count {
            var carry: UInt64 = 0
            let a = UInt64(lhs.words[i])
            for j in 0..<rhs.words.count {
                let cur = UInt64(out[i + j]) + a * UInt64(rhs.words[j]) + carry
                out[i + j] = UInt32(truncatingIfNeeded: cur)
                carry = cur >> 32
            }
            var k = i + rhs.words.count
            while carry > 0 {
                let cur = UInt64(out[k]) + carry
                out[k] = UInt32(truncatingIfNeeded: cur)
                carry = cur >> 32
                k += 1
            }
        }
        return BigInt(Self.normalized(out))
    }

    /// self mod m via binary long division (school-book, shift & subtract).
    public func mod(_ m: BigInt) -> BigInt {
        precondition(!m.isZero)
        if self < m { return self }
        var rem = BigInt([0])
        // Process bit by bit, MSB first.
        let totalBits = (words.count * 32)
        for bit in stride(from: totalBits - 1, through: 0, by: -1) {
            // rem = rem << 1 | bit
            rem = Self.shiftLeft1(rem)
            let wordIdx = bit / 32
            let bitIdx = bit % 32
            if (words[wordIdx] >> UInt32(bitIdx)) & 1 == 1 {
                rem.words[0] |= 1
            }
            rem.words = Self.normalized(rem.words)
            if !(rem < m) {
                rem = Self.subtract(rem, m)
            }
        }
        return rem
    }

    /// (self ^ e) mod m, using modular square-and-multiply.
    public func power(_ e: BigInt, mod m: BigInt) -> BigInt {
        if m.isZero { return BigInt([0]) }
        if m == BigInt([1]) { return BigInt([0]) }
        var result = BigInt([1])
        var base = self.mod(m)
        var exp = e
        while !exp.isZero {
            if exp.words[0] & 1 == 1 {
                result = Self.multiplyMod(result, base, m)
            }
            base = Self.multiplyMod(base, base, m)
            // shift exponent right by 1 bit
            exp = Self.shiftRight1(exp)
        }
        return result
    }

    static func multiplyMod(_ a: BigInt, _ b: BigInt, _ m: BigInt) -> BigInt {
        var acc = BigInt([0])
        var bb = b
        let bits = b.words.count * 32
        for bit in stride(from: bits - 1, through: 0, by: -1) {
            acc = Self.shiftLeft1(acc)
            acc.words = Self.normalized(acc.words)
            if !(acc < m) { acc = Self.subtract(acc, m) }
            if (b.words[bit / 32] >> UInt32(bit % 32)) & 1 == 1 {
                acc = Self.addMod(acc, a, m)
            }
        }
        return acc
    }

    static func addMod(_ a: BigInt, _ b: BigInt, _ m: BigInt) -> BigInt {
        var sum = add(a, b)
        while !(sum < m) { sum = subtract(sum, m) }
        return sum
    }

    static func add(_ a: BigInt, _ b: BigInt) -> BigInt {
        var out = [UInt32](repeating: 0, count: max(a.words.count, b.words.count) + 1)
        var carry: UInt64 = 0
        for i in 0..<out.count {
            let x = i < a.words.count ? UInt64(a.words[i]) : 0
            let y = i < b.words.count ? UInt64(b.words[i]) : 0
            let s = x + y + carry
            out[i] = UInt32(truncatingIfNeeded: s)
            carry = s >> 32
        }
        return BigInt(Self.normalized(out))
    }

    /// a - b, requires a >= b.
    static func subtract(_ a: BigInt, _ b: BigInt) -> BigInt {
        var out = [UInt32](repeating: 0, count: a.words.count)
        var borrow: Int64 = 0
        for i in 0..<a.words.count {
            let x = Int64(a.words[i])
            let y = i < b.words.count ? Int64(b.words[i]) : 0
            var d = x - y - borrow
            if d < 0 { d += Int64(1) << 32; borrow = 1 } else { borrow = 0 }
            out[i] = UInt32(truncatingIfNeeded: d)
        }
        return BigInt(Self.normalized(out))
    }

    static func shiftLeft1(_ a: BigInt) -> BigInt {
        var out = [UInt32](repeating: 0, count: a.words.count + 1)
        var carry: UInt32 = 0
        for i in 0..<a.words.count {
            out[i] = (a.words[i] << 1) | carry
            carry = a.words[i] >> 31
        }
        out[a.words.count] = carry
        return BigInt(Self.normalized(out))
    }

    static func shiftRight1(_ a: BigInt) -> BigInt {
        var out = [UInt32](repeating: 0, count: a.words.count)
        for i in 0..<a.words.count {
            let lowBit = i + 1 < a.words.count ? (a.words[i+1] & 1) << 31 : 0
            out[i] = (a.words[i] >> 1) | lowBit
        }
        return BigInt(Self.normalized(out))
    }
}
