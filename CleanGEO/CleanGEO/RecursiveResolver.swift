import Foundation

/// TODO (phase 2): iterative resolver root -> TLD -> authoritative.
/// Requirements: TTL cache, 0x20 case randomisation, bailiwick checks, anti-loop (max depth),
/// UDP with TCP fallback on TC bit, optional DNSSEC validation via DNSSECValidating.
protocol RecursiveResolving {
    func resolve(name: String, type: UInt16) async throws -> Data
}
