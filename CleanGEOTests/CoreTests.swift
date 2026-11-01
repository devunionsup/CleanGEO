import XCTest

final class CoreTests: XCTestCase {
    func testCompilerBlockAndException() throws {
        let out = FilterCompiler.compile("||ads.example.com^\n@@||ok.example.com^\nsite.ge##.banner\n! comment")
        let arr = try JSONSerialization.jsonObject(with: out.json) as! [[String: Any]]
        XCTAssertEqual(arr.count, 3)
        let last = (arr.last!["action"] as! [String: Any])["type"] as! String
        XCTAssertEqual(last, "ignore-previous-rules")     // exceptions must come last
        XCTAssertTrue(out.domainList.contains("a\tads.example.com"))
        XCTAssertTrue(out.domainList.contains("@\tok.example.com"))
    }

    func testRuleCap() {
        let big = (0..<160_000).map { "||d\($0).test^" }.joined(separator: "\n")
        XCTAssertLessThanOrEqual(FilterCompiler.compile(big).ruleCount, FilterCompiler.maxRules)
    }

    func testQuestionParseAndBlockedResponse() throws {
        let q = DNSWire.buildQuery(name: "Ads.Example.com", type: 1, id: 0x1234)
        let parsed = try XCTUnwrap(DNSWire.parseQuestion(q))
        XCTAssertEqual(parsed.name, "ads.example.com")
        let r = [UInt8](DNSWire.blockedResponse(for: q, q: parsed))
        XCTAssertEqual(r[0], 0x12); XCTAssertEqual(r[1], 0x34)
        XCTAssertEqual(r[2] & 0x80, 0x80)                 // QR
        XCTAssertEqual(r[7], 1)                           // 1 answer
        XCTAssertEqual(Array(r.suffix(4)), [0, 0, 0, 0])  // 0.0.0.0
    }

    func testAAAAAndOtherTypes() throws {
        let q6 = DNSWire.buildQuery(name: "x.com", type: 28)
        let p6 = try XCTUnwrap(DNSWire.parseQuestion(q6))
        XCTAssertEqual(DNSWire.blockedResponse(for: q6, q: p6).suffix(16).count, 16)
        let qm = DNSWire.buildQuery(name: "x.com", type: 15)
        let pm = try XCTUnwrap(DNSWire.parseQuestion(qm))
        XCTAssertEqual([UInt8](DNSWire.blockedResponse(for: qm, q: pm))[7], 0)  // empty NOERROR
    }
}
