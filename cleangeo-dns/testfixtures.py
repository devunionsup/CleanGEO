"""DNSSEC fixtures shared by the test suites: real keys, real signatures.

Lives at the top level, next to the suites, because the runner copies a bounded
amount of Python into its sandbox and a helper inside a subdirectory was left
behind there — present in the repository, missing at run time.

Genuine ECDSA P-256 keys and genuine RRSIGs: a test only passes when
`cryptography` actually verifies a signature this module really produced, so the
resolver's validator is exercised rather than mocked.

Zones built here:

    .  --DS-->  test.  --DS-->  example.test.   (fully signed)
                         \\
                          NSEC ->  open.test.    (deliberately unsigned)

The signature window is relative to the current time, so fixtures stay valid
whenever they are run; one test deliberately builds a closed window.
"""
from __future__ import annotations

import importlib.util
import pathlib
import struct
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = pathlib.Path(__file__).resolve().parent


def load(name: str, filename: str = None):
    """Import a sibling module by path, cached in sys.modules."""
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(name, HERE / (filename or name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


R = load("cleangeo_resolver", "resolver.py")

NOW = int(time.time())
INCEPTION = NOW - 86_400
EXPIRATION = NOW + 7 * 86_400

# Root trust anchors as published by IANA: the suites assert these rather than
# trusting the resolver's own description of itself.
ROOT_ANCHORS = {
    "KSK-2017": (20326, 8, 2,
                 "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
    "KSK-2024": (38696, 8, 2,
                 "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
}


class SigningKey:
    """An ECDSA P-256 DNSKEY; signs in DNSSEC's raw r||s form."""

    def __init__(self, flags: int = 257):
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.algorithm = R.ALG_ECDSAP256
        self.flags = flags
        self.rdata = struct.pack(">HBB", flags, 3, self.algorithm) + self.public_bytes
        self.tag = R.key_tag(self.rdata)

    @property
    def public_bytes(self) -> bytes:
        numbers = self._key.public_key().public_numbers()
        return (b"\x04" + numbers.x.to_bytes(32, "big")
                + numbers.y.to_bytes(32, "big"))

    def sign(self, data: bytes) -> bytes:
        der = self._key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def bitmap(types) -> bytes:
    windows = {}
    for rtype in types:
        window, bit = divmod(rtype, 256)
        block = windows.setdefault(window, bytearray(32))
        block[bit // 8] |= 0x80 >> (bit % 8)
    out = b""
    for window in sorted(windows):
        block = windows[window]
        while block and block[-1] == 0:
            block.pop()
        out += bytes([window, len(block)]) + bytes(block)
    return out


def ds_rdata(key: SigningKey, owner: str, digest_type: int = None) -> bytes:
    digest_type = R.DIGEST_SHA256 if digest_type is None else digest_type
    return (struct.pack(">HBB", key.tag, key.algorithm, digest_type)
            + R.ds_digest(owner, key.rdata, digest_type))


def nsec_rdata(next_name: str, types) -> bytes:
    return R.name_to_wire(next_name) + bitmap(types)


def soa_rdata(zone: str) -> bytes:
    return (R.name_to_wire("ns1." + zone) + R.name_to_wire("hostmaster." + zone)
            + struct.pack(">IIIII", 1, 3600, 600, 86400, 300))


def rrsig_rdata(key: SigningKey, owner: str, rtype: int, records, signer: str, *,
                labels: int = None, inception: int = None, expiration: int = None,
                corrupt: bool = False) -> bytes:
    """Sign one RRset exactly as RFC 4034 3.1.8.1 describes."""
    labels = len(R.labels_of(R.canonical(owner))) if labels is None else labels
    inception = INCEPTION if inception is None else inception
    expiration = EXPIRATION if expiration is None else expiration
    ttl = records[0][2]
    prefix = (struct.pack(">HBBIIIH", rtype, key.algorithm, labels, ttl, expiration,
                          inception, key.tag) + R.name_to_wire(signer))
    body = b""
    for owner_name, _rtype, record_ttl, rdata in sorted(
            {(rec[0], rec[1], rec[2], rec[3]) for rec in records}, key=lambda r: r[3]):
        body += (R.name_to_wire(R.canonical(owner_name))
                 + struct.pack(">HHIH", rtype, 1, record_ttl, len(rdata)) + rdata)
    signature = key.sign(prefix + body)
    if corrupt:
        signature = signature[:8] + b"\xff" * 16 + signature[24:]
    return prefix + signature


def wire_record(owner: str, rtype: int, ttl: int, rdata: bytes) -> bytes:
    return (R.name_to_wire(owner)
            + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata)


def wire_message(qid: int, flags: int, question=None, answers=(), authority=(),
                 additional=()) -> bytes:
    header = struct.pack(">HHHHHH", qid, flags, 1 if question else 0,
                         len(answers), len(authority), len(additional))
    body = b""
    if question is not None:
        body += R.name_to_wire(question.name) + struct.pack(">HH", question.qtype, 1)
    for owner, qtype, ttl, rdata in list(answers) + list(authority) + list(additional):
        body += wire_record(owner, qtype, ttl, rdata)
    return header + body


class StubTransport:
    """Stands in for the network: exact answers, plus a per-address default."""

    def __init__(self, answers: dict):
        self.answers = answers
        self.seen = []

    def query(self, address: str, payload: bytes, *, tcp: bool = False):
        question = R.parse_message(payload).questions[0]
        key = (address, R.canonical(question.name), question.qtype)
        self.seen.append(key)
        raw = self.answers.get(key)
        if raw is None:
            raise R.ResolveError("stub has no answer for %r" % (key,))
        return R.parse_message(raw)


class TestTree:
    """root -> test. -> example.test., signed with throwaway keys."""

    ROOT_ADDR = "192.0.2.1"
    TLD_ADDR = "192.0.2.2"
    AUTH_ADDR = "192.0.2.3"
    UNSIGNED_ADDR = "192.0.2.9"

    def __init__(self):
        self.root_key = SigningKey()
        self.tld_key = SigningKey()
        self.auth_key = SigningKey()
        self.answers = {}
        self._build()

    def _put(self, address, name, qtype, payload):
        self.answers[(address, R.canonical(name), qtype)] = payload

    def _zone_keys(self, zone, key):
        dnskey = (zone, R.T_DNSKEY, 3600, key.rdata)
        return [dnskey, (zone, R.T_RRSIG, 3600,
                         rrsig_rdata(key, zone, R.T_DNSKEY, [dnskey], zone))]

    def _signed(self, zone, key, records, corrupt=False):
        out = list(records)
        for rtype in {rec[1] for rec in records}:
            same = [rec for rec in records if rec[1] == rtype]
            out.append((same[0][0], R.T_RRSIG, same[0][2],
                        rrsig_rdata(key, same[0][0], rtype, same, zone,
                                    corrupt=corrupt)))
        return out

    def _glue(self, child):
        return {"test.": bytes([192, 0, 2, 2]),
                "example.test.": bytes([192, 0, 2, 3]),
                "open.test.": bytes([192, 0, 2, 9])}[child]

    def _referral(self, zone, key, question, child, signed_child):
        authority = [(child, R.T_NS, 3600, R.name_to_wire("ns1." + child))]
        if signed_child is not None:
            ds = (child, R.T_DS, 3600, ds_rdata(signed_child, child))
            authority += self._signed(zone, key, [ds])
        else:
            # A signed NSEC over the child with no DS in its bitmap proves the
            # child is unsigned. The signature makes the denial trustworthy.
            nsec = (child, R.T_NSEC, 3600,
                    nsec_rdata("zzz." + zone if zone != "." else "zzz.",
                               [R.T_NS, R.T_RRSIG, R.T_NSEC]))
            authority += self._signed(zone, key, [nsec])
        glue = ("ns1." + child, R.T_A, 3600, self._glue(child))
        return wire_message(0x1000, 0x8000, question, (), authority, [glue])

    def _build(self):
        self.root_keys = self._zone_keys(".", self.root_key)
        self._put(self.ROOT_ADDR, ".", R.T_DNSKEY,
                  wire_message(0x1001, 0x8000, R.Question(".", R.T_DNSKEY),
                               self.root_keys))
        self.root_referral = self._referral(
            ".", self.root_key, R.Question("test.", R.T_NS), "test.", self.tld_key)
        self._put(self.ROOT_ADDR, "test.", R.T_NS, self.root_referral)
        for name in ("www.example.test.", "beaten.example.test.",
                     "nothing.example.test.", "host.open.test."):
            self._put(self.ROOT_ADDR, name, R.T_A, self.root_referral)

        self.tld_keys = self._zone_keys("test.", self.tld_key)
        self._put(self.TLD_ADDR, "test.", R.T_DNSKEY,
                  wire_message(0x2221, 0x8000, R.Question("test.", R.T_DNSKEY),
                               self.tld_keys))

        example = self._referral("test.", self.tld_key,
                                 R.Question("www.example.test.", R.T_A),
                                 "example.test.", self.auth_key)
        for name in ("www.example.test.", "beaten.example.test.",
                     "nothing.example.test."):
            self._put(self.TLD_ADDR, name, R.T_A, example)
        self._put(self.TLD_ADDR, "example.test.", R.T_DS,
                  wire_message(0x2222, 0x8000,
                               R.Question("example.test.", R.T_DS),
                               self._signed("test.", self.tld_key, [
                                   ("example.test.", R.T_DS, 3600,
                                    ds_rdata(self.auth_key, "example.test."))])))

        self._put(self.TLD_ADDR, "host.open.test.", R.T_A,
                  self._referral("test.", self.tld_key,
                                 R.Question("host.open.test.", R.T_A),
                                 "open.test.", None))
        self._build_unsigned()

        self.zone_keys = self._zone_keys("example.test.", self.auth_key)
        self._put(self.AUTH_ADDR, "example.test.", R.T_DNSKEY,
                  wire_message(0x3331, 0x8000,
                               R.Question("example.test.", R.T_DNSKEY),
                               self.zone_keys))

        self.www_a = ("www.example.test.", R.T_A, 300, bytes([203, 0, 113, 7]))
        self._put(self.AUTH_ADDR, "www.example.test.", R.T_A,
                  wire_message(0x3332, 0x8400,
                               R.Question("www.example.test.", R.T_A),
                               self._signed("example.test.", self.auth_key,
                                            [self.www_a])))

        self.forged = ("beaten.example.test.", R.T_A, 300, bytes([203, 0, 113, 66]))
        self._put(self.AUTH_ADDR, "beaten.example.test.", R.T_A,
                  wire_message(0x3333, 0x8000,
                               R.Question("beaten.example.test.", R.T_A),
                               self._signed("example.test.", self.auth_key,
                                            [self.forged], corrupt=True)))

        zone = "example.test."
        soa = (zone, R.T_SOA, 300, soa_rdata(zone))
        denial = (zone, R.T_NSEC, 300,
                  nsec_rdata("www.example.test.", [R.T_SOA, R.T_NS, R.T_RRSIG,
                                                   R.T_NSEC, R.T_DNSKEY]))
        self._put(self.AUTH_ADDR, "nothing.example.test.", R.T_A,
                  wire_message(0x3334, 0x8400,
                               R.Question("nothing.example.test.", R.T_A), (),
                               self._signed(zone, self.auth_key, [soa, denial])))

    def _build_unsigned(self):
        """open.test. is delegated without a DS; its data is unsigned."""
        answer = ("host.open.test.", R.T_A, 3600, bytes([192, 0, 2, 9]))
        self._put(self.UNSIGNED_ADDR, "host.open.test.", R.T_A,
                  wire_message(0x4441, 0x8000,
                               R.Question("host.open.test.", R.T_A), [answer]))

    def resolver(self, require_dnssec: bool = True, anchors=None,
                 corrupt_anchor: bool = False):
        if anchors is None:
            anchors = [(self.root_key.tag, self.root_key.algorithm, R.DIGEST_SHA256,
                        R.ds_digest(".", self.root_key.rdata,
                                    R.DIGEST_SHA256).hex().upper())]
        if corrupt_anchor:
            anchors = [(tag, alg, dtype, "00" * 32)
                       for tag, alg, dtype, _digest in anchors]
        self.transport = StubTransport(self.answers)
        return R.Resolver(transport=self.transport, trust_anchors=anchors,
                          root_hints=[self.ROOT_ADDR],
                          require_dnssec=require_dnssec)

    def replace_answer(self, address, name, qtype, payload):
        """Override a scripted answer using the canonical key format."""
        self.answers[(address, R.canonical(name), qtype)] = payload
