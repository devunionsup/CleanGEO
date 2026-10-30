"""Resolver + DNSSEC tests. No network required; every signature is real.

Run: python test_resolver.py   (from the cleangeo-dns directory)
     python -m unittest tests.test_resolver
"""
from __future__ import annotations

import importlib.util
import pathlib
import struct
import sys
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))


def _support():
    """Load tests/_load.py by path.

    Importing it as `tests._load` depends on package resolution the runner does
    not always give us, so the fixtures module is loaded explicitly. It returns
    the resolver module and the DNSSEC fixtures.
    """
    name = "cleangeo_support"
    if name in sys.modules:
        return sys.modules[name]
    path = _HERE / "tests" / "_load.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


F = _support()
R = F.R


class WireFormatTests(unittest.TestCase):
    def test_name_roundtrip(self):
        for name in ("example.com", "a.b.c.d.example", "xn--bcher-kva.example"):
            encoded = R.name_to_wire(name)
            name_back, end = R.wire_to_name(encoded, 0)
            self.assertEqual(R.canonical(name_back), name)
            self.assertEqual(end, len(encoded))

    def test_compression_pointer(self):
        suffix = R.name_to_wire("example.com")
        suffix_at = 6  # right after "\x03www" + a two-byte pointer
        packet = b"\x03www" + struct.pack(">H", 0xC000 | suffix_at)
        packet += b"\x00" * (suffix_at - len(packet)) + suffix
        name, _end = R.wire_to_name(packet, 0)
        self.assertEqual(R.canonical(name), "www.example.com")

    def test_rejects_runaway_compression(self):
        packet = b"\xc0\x00" + b"\x00" * 10
        with self.assertRaises(R.ResolveError):
            R.wire_to_name(packet, 0)

    def test_key_tag_is_deterministic_and_bounded(self):
        # RFC 4034 Appendix B checksum: alternating low/high bytes, folded.
        self.assertEqual(R.key_tag(b"\x01\x02\x03\x04"), 0x0201 + 0x0403)
        self.assertLessEqual(R.key_tag(b"\xff" * 64), 0xFFFF)
        self.assertNotEqual(R.key_tag(b"\x01\x02\x03\x04"),
                            R.key_tag(b"\x02\x01\x03\x04"))
        # Rdata shorter than the flag/algorithm header is not a real key.
        self.assertEqual(R.key_tag(b"\x01\x02"), 0)

    def test_bitmap_roundtrip(self):
        data = F.bitmap([R.T_NS, R.T_DS, R.T_RRSIG, R.T_DNSKEY])
        self.assertEqual(R.bitmap_types(data), {R.T_NS, R.T_DS, R.T_RRSIG, R.T_DNSKEY})

    def test_nsec_covers(self):
        self.assertTrue(R.nsec_covers("a.example.", "c.example.", "b.example."))
        self.assertFalse(R.nsec_covers("a.example.", "c.example.", "d.example."))
        self.assertFalse(R.nsec_covers("a.example.", "c.example.", "a.example."))

    def test_parse_rejects_truncated_rdata(self):
        message = F.wire_message(1, 0x8000, R.Question("a.example.", R.T_A),
                                 [("a.example.", R.T_A, 60, bytes([1, 2, 3, 4]))])
        with self.assertRaises(R.ResolveError):
            R.parse_message(message[:-2])


def struct_pack_pointer(offset: int) -> bytes:
    import struct
    return struct.pack(">H", 0xC000 | offset)


class SignedTreeTests(unittest.TestCase):
    def setUp(self):
        self.tree = F.TestTree()
        self.resolver = self.tree.resolver()

    def test_validates_a_signed_answer_end_to_end(self):
        answer = self.resolver.resolve("www.example.test.", R.T_A)
        self.assertEqual(answer.rcode, 0)
        self.assertEqual(answer.security, "validated")
        self.assertTrue(answer.records[0].validated)
        self.assertEqual(answer.records[0].parsed, "203.0.113.7")

    def test_walks_the_delegation_chain(self):
        answer = self.resolver.resolve("www.example.test.", R.T_A)
        self.assertEqual(answer.chain, [".", "test", "example.test"])

    def test_only_talks_to_authoritative_servers(self):
        self.resolver.resolve("www.example.test.", R.T_A)
        seen = {address for address, _name, _type in self.resolver.transport.seen}
        self.assertTrue(seen <= {F.TestTree.ROOT_ADDR, F.TestTree.TLD_ADDR,
                                 F.TestTree.AUTH_ADDR})

    def test_forged_signature_is_bogus_not_answered(self):
        with self.assertRaises(R.Bogus):
            self.resolver.resolve("beaten.example.test.", R.T_A)
        self.assertEqual(self.resolver.stats["bogus"], 1)

    def test_unsigned_zone_is_reported_insecure_not_validated(self):
        answer = self.resolver.resolve("host.open.test.", R.T_A)
        self.assertEqual(answer.security, "insecure")
        self.assertFalse(answer.validated)

    def test_corrupt_root_anchor_makes_everything_bogus(self):
        resolver = self.tree.resolver(corrupt_anchor=True)
        with self.assertRaises(R.ResolveError):
            resolver.resolve("www.example.test.", R.T_A)

    def test_missing_answer_is_nodata_not_failure(self):
        answer = self.resolver.resolve("nothing.example.test.", R.T_A)
        self.assertEqual(answer.rcode, 0)
        self.assertEqual(answer.records, [])
        self.assertTrue(any("NODATA" in note for note in answer.notes))
    def test_cache_hit_does_not_requery(self):
        self.resolver.resolve("www.example.test.", R.T_A)
        before = len(self.resolver.transport.seen)
        self.resolver.resolve("www.example.test.", R.T_A)
        self.assertEqual(len(self.resolver.transport.seen), before)
        self.assertEqual(self.resolver.stats["cacheHits"], 1)

    def test_replay_of_old_signature_fails_validity_window(self):
        # An RRSIG whose window has already closed must not validate, even
        # though its signature bytes are genuine.
        tree = F.TestTree()
        record = ("www.example.test.", R.T_A, 300, bytes([203, 0, 113, 7]))
        expired_sig = F.rrsig_rdata(tree.auth_key, "www.example.test.", R.T_A,
                                    [record], "example.test.",
                                    inception=F.NOW - 1000,
                                    expiration=F.NOW - 500)
        tree.replace_answer(
            tree.AUTH_ADDR, "www.example.test.", R.T_A,
            F.wire_message(0x9999, 0x8000,
                           R.Question("www.example.test.", R.T_A),
                           [record, ("www.example.test.", R.T_RRSIG, 300, expired_sig)]))
        with self.assertRaises((R.Bogus, R.Unvalidated)):
            tree.resolver().resolve("www.example.test.", R.T_A)


class AnswerHelpersTests(unittest.TestCase):
    def setUp(self):
        self.tree = F.TestTree()
        self.resolver = self.tree.resolver()

    def test_answer_query_sets_ad_only_when_validated(self):
        wire = R.build_query("www.example.test.", R.T_A, rd=True)
        response = R.answer_query(self.resolver, wire)
        flags = int.from_bytes(response[2:4], "big")
        self.assertTrue(flags & 0x8000)
        self.assertTrue(flags & 0x0020, "AD bit must be set for validated data")
        parsed = R.parse_message(response)
        self.assertEqual(parsed.answers[0].parsed, "203.0.113.7")

    def test_answer_query_servfails_on_bogus(self):
        wire = R.build_query("beaten.example.test.", R.T_A, rd=True)
        response = R.answer_query(self.resolver, wire)
        parsed = R.parse_message(response)
        self.assertEqual(parsed.rcode, 2)
        self.assertFalse(parsed.flags & 0x0020, "SERVFAIL must never carry AD")

    def test_malformed_query_gets_formerr_like_reply(self):
        response = R.answer_query(self.resolver, b"\x00")
        self.assertEqual(R.parse_message(response).rcode, 2)

    def test_oversized_response_is_truncated_with_tc(self):
        wire = R.build_query("www.example.test.", R.T_A, rd=True)
        response = R.answer_query(self.resolver, wire, max_udp=8)
        self.assertTrue(int.from_bytes(response[2:4], "big") & 0x0200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
