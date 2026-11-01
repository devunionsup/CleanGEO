import Foundation

/// TODO (phase 2): full DNSSEC chain validation.
/// Chain: IANA root KSK (key tags 20326, 38696) -> DS -> DNSKEY -> RRSIG.
/// Algorithms: RSA-SHA256 (8), RSA-SHA512 (10), ECDSA P-256 (13), ECDSA P-384 (14), Ed25519 (15).
/// Use Security.framework (SecKeyVerifySignature) / CryptoKit; check inception/expiration; RFC 4034 canonical form.
protocol DNSSECValidating {
    func validate(response: Data, for name: String, type: UInt16) async -> Bool
}

struct DNSSECValidator: DNSSECValidating {
    func validate(response: Data, for name: String, type: UInt16) async -> Bool {
        fatalError("Not implemented — see TODO above")
    }
}
