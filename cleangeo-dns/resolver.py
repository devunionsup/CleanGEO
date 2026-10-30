"""CleanGEO iterative, DNSSEC-validating resolver.

Independence
------------
This module never forwards a query to a public recursive resolver. It walks the
delegation chain itself: root servers -> TLD servers -> authoritative servers.
The only hosts it talks to are (a) the 13 root servers from the IANA hints and
(b) authoritative nameservers named by the delegations it follows. There is no
upstream resolver setting anywhere, on purpose.

That independence has a cost that cannot be configured away: the authoritative
servers see this host's IP address and the queries it makes. `NETWORK-PRIVACY.md`
documents that exposure rather than hiding it.

Validation
----------
DNSSEC is validated from the root trust anchor down: root DNSKEY against the
built-in anchors, every child DNSKEY against its parent's DS, denial of DS
through NSEC/NSEC3, and the final answer RRset against its zone's keys.

Three outcomes, kept distinct because collapsing them is how "DNSSEC support"
becomes a lie:

* validated  - a full chain of signatures verifies.
* insecure   - a signed parent proves by signed denial that the child is
               unsigned. The data is *not* protected by DNSSEC; that is a fact
               about the zone, not a failure of this resolver.
* bogus      - signatures exist and do not verify. Always servfail. Never a
               best-effort answer.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field

T_A, T_NS, T_CNAME, T_SOA, T_PTR, T_MX = 1, 2, 5, 6, 12, 15
T_TXT, T_AAAA, T_SRV, T_DS, T_RRSIG, T_NSEC = 16, 28, 33, 43, 46, 47
T_DNSKEY, T_NSEC3, T_NSEC3PARAM, T_TLSA, T_CAA = 48, 50, 51, 52, 257
T_OPT, T_ANY = 41, 255

TYPE_NAMES = {
    T_A: "A", T_NS: "NS", T_CNAME: "CNAME", T_SOA: "SOA", T_PTR: "PTR", T_MX: "MX",
    T_TXT: "TXT", T_AAAA: "AAAA", T_SRV: "SRV", T_DS: "DS", T_RRSIG: "RRSIG",
    T_NSEC: "NSEC", T_DNSKEY: "DNSKEY", T_NSEC3: "NSEC3", T_NSEC3PARAM: "NSEC3PARAM",
    T_TLSA: "TLSA", T_CAA: "CAA", T_OPT: "OPT", T_ANY: "ANY",
}
NAME_TO_TYPE = {v: k for k, v in TYPE_NAMES.items()}

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
          5: "REFUSED"}

ALG_RSASHA1, ALG_RSASHA256, ALG_RSASHA512 = 5, 8, 10
ALG_ECDSAP256, ALG_ECDSAP384, ALG_ED25519 = 13, 14, 15
SUPPORTED_ALGS = {ALG_RSASHA1, ALG_RSASHA256, ALG_RSASHA512, ALG_ECDSAP256,
                  ALG_ECDSAP384, ALG_ED25519}
DIGEST_SHA1, DIGEST_SHA256, DIGEST_SHA384 = 1, 2, 4

# Root trust anchors, taken from https://data.iana.org/root-anchors/root-anchors.xml
# (KSK-2017 tag 20326 and KSK-2024 tag 38696). Pinned on purpose: a resolver
# that trusts whatever key it is handed validates nothing.
ROOT_ANCHORS = [
    (20326, 8, DIGEST_SHA256,
     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
    (38696, 8, DIGEST_SHA256,
     "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
]

# Root hints from https://www.internic.net/domain/named.root
ROOT_HINTS = [
    "198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33",
]


class ResolveError(Exception):
    """Any failure that must surface as SERVFAIL."""


class Bogus(ResolveError):
    """DNSSEC material is present and does not verify."""


class Unvalidated(ResolveError):
    """A signature was required and could not be obtained or verified."""


# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------

def canonical(name: str) -> str:
    return name.rstrip(".").lower()


def name_to_wire(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = b""
    for label in name.split("."):
        raw = label.encode("idna") if not label.isascii() else label.lower().encode()
        if not 0 < len(raw) < 64:
            raise ResolveError("bad label in %r" % name)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def wire_to_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 24:
        raise ResolveError("compression loop")
    labels: list[str] = []
    while True:
        if offset >= len(data):
            raise ResolveError("name runs past packet")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ResolveError("truncated pointer")
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            inner, _ = wire_to_name(data, pointer, depth + 1)
            if inner:
                labels.append(inner)
            offset += 2
            break
        if length & 0xC0:
            raise ResolveError("bad label length")
        raw = data[offset + 1:offset + 1 + length]
        if len(raw) != length:
            raise ResolveError("label runs past packet")
        labels.append(raw.decode("latin-1"))
        offset += 1 + length
    return ".".join(labels), offset


def labels_of(name: str) -> list[str]:
    name = name.rstrip(".")
    return name.split(".") if name else []


def is_subdomain(child: str, parent: str) -> bool:
    child, parent = canonical(child), canonical(parent)
    if parent in ("", "."):
        return True
    return child == parent or child.endswith("." + parent)


# ---------------------------------------------------------------------------
# wire format
# ---------------------------------------------------------------------------

@dataclass
class Question:
    name: str
    qtype: int
    qclass: int = 1


@dataclass
class Record:
    name: str
    rtype: int
    ttl: int
    rdata: bytes
    rclass: int = 1
    parsed: object = None
    rdata_offset: int = -1
    validated: bool = False

    def __str__(self) -> str:
        label = TYPE_NAMES.get(self.rtype, "TYPE%d" % self.rtype)
        value = self.parsed
        if isinstance(value, dict):
            value = " ".join(str(v) for v in value.values())
        elif isinstance(value, bytes):
            value = base64.b64encode(value).decode()
        return "%s %s %s" % (canonical(self.name) or ".", label, value)


@dataclass
class Message:
    id: int = 0
    flags: int = 0
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    additional: list[Record] = field(default_factory=list)
    raw: bytes = b""

    @property
    def rcode(self) -> int:
        return self.flags & 0x0F

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def authoritative(self) -> bool:
        return bool(self.flags & 0x0400)

    @property
    def authenticated(self) -> bool:
        return bool(self.flags & 0x0020)


def build_query(name: str, qtype: int, *, rd: bool = False, edns: bool = True,
                do: bool = False, query_id: int | None = None) -> bytes:
    header = struct.pack(">HHHHHH",
                         secrets.randbits(16) if query_id is None else query_id,
                         0x0100 if rd else 0x0000, 1, 0, 0, 1 if edns else 0)
    body = name_to_wire(name) + struct.pack(">HH", qtype, 1)
    if edns:
        body += b"\x00" + struct.pack(">HHIH", T_OPT, 1232, 0x00008000 if do else 0, 0)
    return header + body


def parse_message(data: bytes) -> Message:
    if len(data) < 12:
        raise ResolveError("short packet")
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    msg = Message(id=qid, flags=flags, raw=data)
    offset = 12
    for _ in range(qdcount):
        name, offset = wire_to_name(data, offset)
        qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
        offset += 4
        msg.questions.append(Question(name, qtype, qclass))
    for section, count in ((msg.answers, ancount), (msg.authority, nscount),
                           (msg.additional, arcount)):
        for _ in range(count):
            name, offset = wire_to_name(data, offset)
            if offset + 10 > len(data):
                raise ResolveError("record header past end")
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if offset + rdlen > len(data):
                raise ResolveError("rdata past end")
            record = Record(name, rtype, ttl, data[offset:offset + rdlen], rclass,
                            rdata_offset=offset)
            offset += rdlen
            parse_rdata(record, data)
            section.append(record)
    return msg


def parse_rdata(record: Record, packet: bytes) -> None:
    offset = record.rdata_offset
    rtype = record.rtype
    if rtype == T_A and len(record.rdata) == 4:
        record.parsed = socket.inet_ntop(socket.AF_INET, record.rdata)
    elif rtype == T_AAAA and len(record.rdata) == 16:
        record.parsed = socket.inet_ntop(socket.AF_INET6, record.rdata)
    elif rtype in (T_NS, T_CNAME, T_PTR):
        record.parsed = canonical(wire_to_name(packet, offset)[0])
    elif rtype == T_MX and len(record.rdata) >= 3:
        preference = struct.unpack(">H", record.rdata[:2])[0]
        record.parsed = {"preference": preference,
                         "exchange": canonical(wire_to_name(packet, offset + 2)[0])}
    elif rtype == T_SRV and len(record.rdata) >= 7:
        priority, weight, port = struct.unpack(">HHH", record.rdata[:6])
        record.parsed = {"priority": priority, "weight": weight, "port": port,
                         "target": canonical(wire_to_name(packet, offset + 6)[0])}
    elif rtype == T_SOA:
        mname, after = wire_to_name(packet, offset)
        rname, after = wire_to_name(packet, after)
        values = struct.unpack(">IIIII", packet[after:after + 20])
        record.parsed = {"mname": canonical(mname), "rname": canonical(rname),
                         "serial": values[0], "refresh": values[1], "retry": values[2],
                         "expire": values[3], "minimum": values[4]}
    elif rtype == T_DS and len(record.rdata) >= 4:
        keytag, algorithm, digest_type = struct.unpack(">HBB", record.rdata[:4])
        record.parsed = {"keytag": keytag, "algorithm": algorithm,
                         "digestType": digest_type, "digest": record.rdata[4:]}
    elif rtype == T_DNSKEY and len(record.rdata) >= 4:
        flags, protocol, algorithm = struct.unpack(">HBB", record.rdata[:4])
        record.parsed = {"flags": flags, "protocol": protocol, "algorithm": algorithm,
                         "publicKey": record.rdata[4:]}
    elif rtype == T_RRSIG and len(record.rdata) >= 18:
        (type_covered, algorithm, labels, original_ttl, expiration, inception,
         keytag) = struct.unpack(">HBBIIIH", record.rdata[:18])
        signer, after = wire_to_name(packet, offset + 18)
        record.parsed = {
            "typeCovered": type_covered, "algorithm": algorithm, "labels": labels,
            "originalTTL": original_ttl, "expiration": expiration,
            "inception": inception, "keytag": keytag, "signer": canonical(signer),
            "signature": packet[after:offset + len(record.rdata)],
            "end": offset + len(record.rdata),
        }
    elif rtype == T_NSEC:
        nxt, after = wire_to_name(packet, offset)
        record.parsed = {"next": canonical(nxt),
                         "types": sorted(bitmap_types(packet[after:offset + len(record.rdata)]))}
    elif rtype == T_NSEC3 and len(record.rdata) >= 5:
        algorithm, nflags, iterations, salt_len = struct.unpack(">BBHB", record.rdata[:5])
        salt = record.rdata[5:5 + salt_len]
        hash_len = record.rdata[5 + salt_len]
        next_hash = record.rdata[6 + salt_len:6 + salt_len + hash_len]
        bitmap = record.rdata[6 + salt_len + hash_len:]
        record.parsed = {"algorithm": algorithm, "flags": nflags,
                         "iterations": iterations, "salt": salt,
                         "nextHash": next_hash, "types": sorted(bitmap_types(bitmap))}
    elif rtype == T_TXT:
        strings = []
        cursor = 0
        while cursor < len(record.rdata):
            length = record.rdata[cursor]
            strings.append(record.rdata[cursor + 1:cursor + 1 + length].decode("utf-8", "replace"))
            cursor += 1 + length
        record.parsed = strings


def bitmap_types(data: bytes) -> set[int]:
    """RFC 4034 4.1.2 type bitmap."""
    types: set[int] = set()
    cursor = 0
    while cursor + 2 <= len(data):
        window = data[cursor]
        length = data[cursor + 1]
        block = data[cursor + 2:cursor + 2 + length]
        for index, byte in enumerate(block):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    types.add(window * 256 + index * 8 + bit)
        cursor += 2 + length
    return types


def canonical_rdata(record: Record) -> bytes:
    """Rdata with embedded names lowercased and uncompressed (RFC 4034 6.2)."""
    rtype, p = record.rtype, record.parsed
    if rtype in (T_NS, T_CNAME, T_PTR) and isinstance(p, str):
        return name_to_wire(p)
    if rtype == T_MX and isinstance(p, dict):
        return struct.pack(">H", p["preference"]) + name_to_wire(p["exchange"])
    if rtype == T_SRV and isinstance(p, dict):
        return (struct.pack(">HHH", p["priority"], p["weight"], p["port"])
                + name_to_wire(p["target"]))
    if rtype == T_SOA and isinstance(p, dict):
        return (name_to_wire(p["mname"]) + name_to_wire(p["rname"])
                + struct.pack(">IIIII", p["serial"], p["refresh"], p["retry"],
                              p["expire"], p["minimum"]))
    return record.rdata


def rrset_key(record: Record) -> tuple[str, int]:
    return canonical(record.name), record.rtype


def group_rrsets(records: list[Record]) -> dict[tuple[str, int], list[Record]]:
    sets: dict[tuple[str, int], list[Record]] = {}
    for record in records:
        if record.rtype == T_RRSIG:
            continue
        sets.setdefault(rrset_key(record), []).append(record)
    return sets


# ---------------------------------------------------------------------------
# DNSSEC primitives
# ---------------------------------------------------------------------------

def key_tag(rdata: bytes) -> int:
    if len(rdata) < 4:
        return 0
    acc = 0
    for index, byte in enumerate(rdata):
        acc += byte if index % 2 == 0 else byte << 8
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


def ds_digest(owner: str, dnskey_rdata: bytes, digest_type: int) -> bytes:
    data = name_to_wire(owner) + dnskey_rdata
    if digest_type == DIGEST_SHA1:
        return hashlib.sha1(data).digest()
    if digest_type == DIGEST_SHA256:
        return hashlib.sha256(data).digest()
    if digest_type == DIGEST_SHA384:
        return hashlib.sha384(data).digest()
    raise Unvalidated("unsupported DS digest type %d" % digest_type)


def verify_signature(algorithm: int, public_key: bytes, signature: bytes,
                     signed_data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    try:
        if algorithm in (ALG_RSASHA1, ALG_RSASHA256, ALG_RSASHA512):
            if not public_key:
                return False
            if public_key[0] == 0:
                if len(public_key) < 3:
                    return False
                exponent_length = struct.unpack(">H", public_key[1:3])[0]
                start = 3
            else:
                exponent_length = public_key[0]
                start = 1
            exponent = int.from_bytes(public_key[start:start + exponent_length], "big")
            modulus = int.from_bytes(public_key[start + exponent_length:], "big")
            if exponent == 0 or modulus == 0:
                return False
            key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
            hash_alg = {ALG_RSASHA1: hashes.SHA1(), ALG_RSASHA256: hashes.SHA256(),
                        ALG_RSASHA512: hashes.SHA512()}[algorithm]
            key.verify(signature, signed_data, padding.PKCS1v15(), hash_alg)
            return True
        if algorithm in (ALG_ECDSAP256, ALG_ECDSAP384):
            if algorithm == ALG_ECDSAP256:
                curve, hash_alg = ec.SECP256R1(), hashes.SHA256()
            else:
                curve, hash_alg = ec.SECP384R1(), hashes.SHA384()
            key = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key)
            # DNSSEC carries ECDSA as r||s; cryptography wants DER.
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            half = len(signature) // 2
            if half * 2 != len(signature):
                return False
            der = encode_dss_signature(int.from_bytes(signature[:half], "big"),
                                       int.from_bytes(signature[half:], "big"))
            key.verify(der, signed_data, ec.ECDSA(hash_alg))
            return True
        if algorithm == ALG_ED25519:
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, signed_data)
            return True
    except (InvalidSignature, ValueError, TypeError, struct.error):
        return False
    return False


def signed_payload(records: list[Record], rrsig: Record) -> bytes:
    p = rrsig.parsed
    owner = canonical(records[0].name)
    owner_labels = labels_of(owner)
    if len(owner_labels) > p["labels"]:
        # Signature covers a wildcard owner name (RFC 4035 5.3.2).
        suffix = owner_labels[len(owner_labels) - p["labels"]:] if p["labels"] else []
        owner = "*." + ".".join(suffix) if suffix else "*"
    rtype = records[0].rtype
    header = struct.pack(">HBBIIIH", p["typeCovered"], p["algorithm"], p["labels"],
                         p["originalTTL"], p["expiration"], p["inception"], p["keytag"])
    header += name_to_wire(p["signer"])
    body = b""
    for rdata in sorted({canonical_rdata(r) for r in records}):
        body += name_to_wire(owner)
        body += struct.pack(">HHIH", rtype, 1, p["originalTTL"], len(rdata)) + rdata
    return header + body


def usable_keys(zone: str, dnskey_records: list[Record]) -> dict[int, tuple[int, bytes]]:
    keys: dict[int, tuple[int, bytes]] = {}
    for record in dnskey_records:
        p = record.parsed or {}
        if p.get("protocol", 3) != 3:
            continue
        if not p.get("flags", 0) & 0x0100:
            continue  # not a zone key
        if p.get("algorithm") not in SUPPORTED_ALGS:
            continue
        keys[key_tag(record.rdata)] = (p["algorithm"], p.get("publicKey") or b"")
    return keys


def verify_rrset(records: list[Record], rrsigs: list[Record],
                 dnskey_records: list[Record], zone: str,
                 now: int | None = None) -> None:
    """Verify one RRset. Raises Bogus when a signature is present but wrong."""
    if not records:
        raise Bogus("empty RRset")
    if not rrsigs:
        raise Unvalidated("%s/%s has no RRSIG" % (
            records[0].name, TYPE_NAMES.get(records[0].rtype, records[0].rtype)))
    current = int(time.time()) if now is None else now
    keys = usable_keys(zone, dnskey_records)
    expired = False
    for rrsig in rrsigs:
        p = rrsig.parsed
        if not p or p["typeCovered"] != records[0].rtype:
            continue
        if canonical(p["signer"]) != canonical(zone):
            continue
        if not is_subdomain(records[0].name, p["signer"]) and canonical(records[0].name) != "*":
            continue
        if p["expiration"] < current or p["inception"] > current:
            # A signature replayed from outside its validity window is exactly
            # what this bound is for; treat it as an expired signature and keep
            # looking, failing closed if nothing else matches.
            expired = True
            continue
        key = keys.get(p["keytag"])
        if not key:
            continue
        if key[0] != p["algorithm"]:
            continue
        if verify_signature(key[0], key[1], p["signature"], signed_payload(records, rrsig)):
            for record in records:
                record.validated = True
            return
        raise Bogus("bad signature on %s/%s by key %d" % (
            records[0].name, TYPE_NAMES.get(records[0].rtype, records[0].rtype), p["keytag"]))
    raise Unvalidated("no usable signature for %s/%s in %s%s" % (
        records[0].name, TYPE_NAMES.get(records[0].rtype, records[0].rtype), zone,
        " (a signature matched but was outside its validity window)" if expired else ""))


# ---------------------------------------------------------------------------
# NSEC / NSEC3 denial
# ---------------------------------------------------------------------------

def nsec_covers(owner: str, next_name: str, qname: str) -> bool:
    """True when qname falls strictly inside the NSEC interval (owner, next)."""
    owner, next_name, qname = canonical(owner), canonical(next_name), canonical(qname)

    def rank(name: str) -> tuple:
        labels = labels_of(name)
        return (len(labels),) + tuple(reversed(labels))

    if owner == next_name:  # single-name zone: covers everything but itself
        return qname != owner
    return rank(owner) < rank(qname) < rank(next_name)


def nsec3_hash(name: str, salt: bytes, iterations: int) -> bytes:
    digest = name_to_wire(name)
    salt = salt or b""
    value = hashlib.sha1(digest + salt).digest()
    for _ in range(iterations):
        value = hashlib.sha1(value + salt).digest()
    return value


def nsec3_covers(owner_label: str, next_hash: bytes, qhash: bytes) -> bool:
    owner = base64.b32decode(owner_label.upper() + "=" * (-len(owner_label) % 8))
    if owner < next_hash:
        return owner < qhash < next_hash
    return qhash > owner or qhash < next_hash  # wrap-around


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

class Transport:
    """Plain DNS/53 to authoritative servers. This is not a privacy boundary.

    The TLS tunnel protects the client->server leg. Past this point the query is
    ordinary DNS to the zone's own servers, as the protocol requires.
    """

    def __init__(self, timeout: float = 3.0, attempts: int = 2):
        self.timeout = timeout
        self.attempts = attempts
        self.query_count = 0

    def query(self, address: str, payload: bytes, *, tcp: bool = False) -> Message:
        last: Exception | None = None
        for attempt in range(self.attempts):
            try:
                self.query_count += 1
                data = self._tcp(address, payload) if tcp else self._udp(address, payload)
                return parse_message(data)
            except (OSError, ResolveError) as exc:
                last = exc
                if attempt + 1 < self.attempts:
                    time.sleep(0.1 * (attempt + 1))
        raise ResolveError("authoritative %s unreachable (%s)" % (address, last))

    def _udp(self, address: str, payload: bytes) -> bytes:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(payload, (address, 53))
            data, _ = sock.recvfrom(4096)
            return data

    def _tcp(self, address: str, payload: bytes) -> bytes:
        with socket.create_connection((address, 53), timeout=self.timeout) as sock:
            sock.sendall(struct.pack(">H", len(payload)) + payload)
            length = struct.unpack(">H", self._read(sock, 2))[0]
            return self._read(sock, length)

    @staticmethod
    def _read(sock, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            if not chunk:
                raise ResolveError("connection closed early")
            data += chunk
        return data


# ---------------------------------------------------------------------------
# resolver
# ---------------------------------------------------------------------------

@dataclass
class Answer:
    rcode: int
    records: list[Record]
    security: str            # "validated" means a full signature chain verified.
    chain: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def validated(self) -> bool:
        """True only when the chain verified and every answer record was signed."""
        if self.security != "validated":
            return False
        if not self.records:
            # NXDOMAIN or NODATA: accepted only after the denial was verified.
            return not self.notes or not any(n.startswith("UNVALIDATED")
                                            for n in self.notes)
        return all(record.validated for record in self.records)

    def to_dict(self) -> dict:
        return {"rcode": RCODES.get(self.rcode, str(self.rcode)),
                "validation": self.security,
                "chain": self.chain,
                "notes": self.notes,
                "answers": [str(record) for record in self.records]}


class Resolver:
    """Iterative resolver with DNSSEC validation and a small answer cache."""

    def __init__(self, *, transport=None, trust_anchors=None, root_hints=None,
                 require_dnssec: bool = True, negative_ttl_cap: int = 300,
                 cache_ttl: int = 300):
        self.transport = transport or Transport()
        self.anchors = list(ROOT_ANCHORS if trust_anchors is None else trust_anchors)
        self.hints = list(ROOT_HINTS if root_hints is None else root_hints)
        self.require_dnssec = require_dnssec
        self._keys: dict[str, tuple[float, list[Record]]] = {}
        self._cache: dict[tuple[str, int], tuple[float, "Answer"]] = {}
        self._cache_cap = 512
        self._cache_ttl_default = cache_ttl
        self._cache_ttl_cap = max(cache_ttl, negative_ttl_cap)
        self.stats = {"queries": 0, "cacheHits": 0, "validatedRrsets": 0,
                      "bogus": 0, "insecureZones": 0, "servfail": 0}

    # -- public ----------------------------------------------------------
    def resolve(self, name: str, qtype: int) -> "Answer":
        self.stats["queries"] += 1
        target = canonical(name)
        cached = self._cache.get((target, qtype))
        if cached and cached[0] > time.time():
            self.stats["cacheHits"] += 1
            return cached[1]
        try:
            answer = self._resolve(target, qtype, depth=0)
        except Bogus:
            self.stats["bogus"] += 1
            raise
        self._store(target, qtype, answer)
        return answer

    # -- internals -------------------------------------------------------
    def _store(self, name: str, qtype: int, answer: "Answer") -> None:
        ttl = self._cache_ttl_default
        if answer.records:
            ttl = min([record.ttl for record in answer.records] or [ttl])
        ttl = max(0, min(ttl, self._cache_ttl_cap))
        if ttl == 0:
            return
        if len(self._cache) >= self._cache_cap:
            self._cache.clear()
        self._cache[(name, qtype)] = (time.time() + ttl, answer)

    def _resolve(self, target: str, qtype: int, depth: int) -> "Answer":
        if depth > 8:
            raise ResolveError("CNAME chain too deep for %s" % target)
        zone, servers, keys, secure = ".", list(self.hints), None, True
        if self.require_dnssec:
            # Validation starts at the trust anchor, so the root keys come first.
            keys = self._root_keys()
        chain: list[str] = ["."]
        for _hop in range(24):
            response = self._ask(servers, target, qtype, dnssec=secure)
            if response is None:
                raise ResolveError("no authoritative response for %s" % target)

            if response.rcode == 3 or response.answers or (
                    response.authority and any(r.rtype == T_SOA for r in response.authority)):
                return self._finish(response, target, qtype, zone, keys, secure, chain,
                                    depth)

            referral = [r for r in response.authority if r.rtype == T_NS]
            if not referral:
                raise ResolveError("no referral for %s in %s" % (target, zone))
            child = canonical(referral[0].name)
            if not is_subdomain(target, child) or child == zone:
                raise ResolveError("referral for %s does not descend from %s" % (child, zone))

            glue = [r.parsed for r in response.additional
                    if r.rtype == T_A and r.parsed and r.name in
                    {canonical(n.parsed or "") for n in referral}]
            addresses = [address for address in glue if address]
            if not addresses:
                addresses = self._nameserver_addresses(referral, secure, chain)

            child_keys: list[Record] | None = None
            if secure and self.require_dnssec:
                child_keys, child_secure = self._delegation(response, zone, keys, child,
                                                            addresses)
                secure = child_secure
            if not addresses:
                # No usable address means we cannot follow the chain at all.
                raise ResolveError("nameservers for %s have no reachable address" % child)

            zone, servers, keys = child, addresses, child_keys
            chain.append(child)
        raise ResolveError("delegation loop resolving %s" % target)

    def _ask(self, servers: list[str], target: str, qtype: int, *,
             dnssec: bool) -> Message | None:
        for address in servers[:4]:
            payload = build_query(target, qtype, rd=False, edns=True, do=dnssec)
            try:
                response = self.transport.query(address, payload)
            except ResolveError:
                continue
            if response.truncated:
                try:
                    response = self.transport.query(address, payload, tcp=True)
                except ResolveError:
                    continue
            return response
        return None

    def _nameserver_addresses(self, referral: list[Record], secure: bool,
                              chain: list[str]) -> list[str]:
        """No glue in the referral: resolve the nameserver names ourselves."""
        addresses: list[str] = []
        for record in referral[:2]:
            host = record.parsed
            if not isinstance(host, str):
                continue
            try:
                inner = self._resolve(host, T_A, depth=0)
            except ResolveError:
                continue
            addresses.extend(r.parsed for r in inner.records
                             if r.rtype == T_A and r.parsed)
            chain.extend(inner.chain[1:])
        return addresses

    def _finish(self, response: Message, target: str, qtype: int, zone: str,
                keys: list[Record] | None, secure: bool, chain: list[str],
                depth: int) -> "Answer":
        status = "validated" if secure else "insecure"
        if secure and self.require_dnssec:
            self._validate_section(response, zone, keys, response.answers, chain,
                                   required=True)
            if not response.answers:
                self._validate_section(response, zone, keys, response.authority, chain,
                                       required=True)

        if response.rcode == 3:
            return Answer(3, [], "validated" if secure else "insecure", chain)

        answers = list(response.answers)
        if answers and answers[0].rtype == T_CNAME and qtype != T_CNAME:
            cname_target = answers[0].parsed
            if isinstance(cname_target, str) and cname_target != target:
                deeper = self._resolve(cname_target, qtype, depth + 1)
                return Answer(deeper.rcode, answers + deeper.records,
                              deeper.security if secure else "insecure",
                              chain + deeper.chain[1:], deeper.notes)
        if not answers:
            return Answer(0, [], status if secure else "insecure", chain,
                          ["NODATA: the name exists but has no %s record"
                           % TYPE_NAMES.get(qtype, qtype)])
        return Answer(0, answers, status if secure else "insecure", chain)

    def _validate_section(self, response: Message, zone: str, keys: list[Record] | None,
                          section: list[Record], chain: list[str], *,
                          required: bool) -> None:
        if not section:
            return
        rrsets = group_rrsets(section)
        rrsigs = [r for r in section if r.rtype == T_RRSIG]
        for (owner, rtype), records in rrsets.items():
            covering = [r for r in rrsigs if r.parsed and r.parsed["typeCovered"] == rtype
                        and canonical(r.name) == owner]
            if rtype == T_DNSKEY:
                self._verify_dnskey_set(records, covering, owner)
                continue
            zone_keys = keys
            if zone_keys is None:
                if required:
                    raise Unvalidated("no keys available for %s" % zone)
                continue
            if not covering:
                if required:
                    raise Unvalidated("%s/%s unsigned in a signed zone" % (
                        owner, TYPE_NAMES.get(rtype, rtype)))
                continue
            verify_rrset(records, covering, zone_keys, zone)
            self.stats["validatedRrsets"] += 1

    def _verify_dnskey_set(self, records: list[Record], covering: list[Record],
                           owner: str) -> None:
        if not covering:
            raise Unvalidated("DNSKEY set for %s is unsigned" % owner)
        verify_rrset(records, covering, records, owner)
        self.stats["validatedRrsets"] += 1
        if canonical(owner) == ".":
            if not any(self._matches_anchor(record) for record in records):
                raise Bogus("root DNSKEY matches no trust anchor")

    def _anchor_match(self, record: Record) -> bool:
        return any(key_tag(record.rdata) == tag and
                   ds_digest(".", record.rdata, digest_type).hex().upper() == digest.upper()
                   for tag, _algorithm, digest_type, digest in self.anchors)

    def _root_keys(self) -> list[Record]:
        cached = self._keys.get(".")
        if cached and cached[0] > time.time():
            return cached[1]
        response = self._ask(list(self.hints), ".", T_DNSKEY, dnssec=True)
        if response is None:
            raise ResolveError("root servers unreachable")
        keys = [r for r in response.answers if r.rtype == T_DNSKEY]
        sigs = [r for r in response.answers if r.rtype == T_RRSIG]
        if not keys:
            raise Unvalidated("root DNSKEY unavailable")
        self._verify_dnskey_set(keys, sigs, ".")
        if not any(self._matches_anchor(record) for record in keys):
            # The self-signature proved internal consistency; the anchors decide
            # whether this root is the root we trust. Never skip this.
            raise Bogus("root DNSKEY matches no configured trust anchor")
        self._remember_keys(".", keys)
        return keys

    def _remember_keys(self, zone: str, keys: list[Record]) -> None:
        ttl = min([record.ttl for record in keys] or [3600])
        self._keys[canonical(zone)] = (time.time() + max(60, min(ttl, 86400)), keys)

    def _delegation(self, response: Message, parent: str,
                    parent_keys: list[Record] | None, child: str,
                    addresses: list[str]) -> tuple[list[Record] | None, bool]:
        """Return (child keys, chain still secure). Enforces DS or signed denial."""
        ds_records = [r for r in response.authority if r.rtype == T_DS
                      and canonical(r.name) == child]
        ds_sigs = [r for r in response.authority if r.rtype == T_RRSIG and r.parsed
                   and r.parsed["typeCovered"] == T_DS and canonical(r.name) == child]
        denial = [r for r in response.authority if r.rtype in (T_NSEC, T_NSEC3)]

        if ds_records:
            if parent_keys is None:
                raise Unvalidated("no parent keys to verify the DS for %s" % child)
            verify_rrset(ds_records, ds_sigs, parent_keys, parent)
            self.stats["validatedRrsets"] += 1
            child_keys = self._fetch_child_keys(child, addresses)
            self._check_keys_against_ds(child, child_keys, ds_records)
            self._remember_keys(child, child_keys)
            return child_keys, True

        if denial:
            if parent_keys is None:
                raise Unvalidated("no parent keys for denial check at %s" % child)
            denial_rrsigs = [r for r in response.authority if r.rtype == T_RRSIG]
            self._validate_section(response, parent, parent_keys,
                                   denial + denial_rrsigs, [], required=True)
            self._denial_proves_no_ds(child, denial, parent)
            self.stats["insecureZones"] += 1
            return None, False

        raise Unvalidated("delegation to %s has neither DS nor signed denial" % child)

    def _denial_proves_no_ds(self, child: str, denial: list[Record], parent: str) -> None:
        for record in denial:
            p = record.parsed or {}
            if record.rtype == T_NSEC:
                if T_DS in p.get("types", []):
                    raise Bogus("NSEC at %s claims a DS for %s" % (record.name, child))
                if canonical(record.name) == child:
                    return
                if nsec_covers(record.name, p.get("next", ""), child):
                    return
            elif record.rtype == T_NSEC3:
                qhash = nsec3_hash(child, p.get("salt", b""), p.get("iterations", 0))
                label = canonical(record.name).split(".")[0]
                if record.name and qhash == base64.b32decode(
                        label.upper() + "=" * (-len(label) % 8)):
                    if T_DS in p.get("types", []):
                        raise Bogus("NSEC3 claims a DS for %s" % child)
                    return
                if nsec3_covers(label, p.get("nextHash", b""), qhash):
                    return
        raise Unvalidated("cannot prove %s is unsigned: denial does not cover it" % child)

    def _fetch_child_keys(self, child: str, addresses: list[str]) -> list[Record]:
        cached = self._keys.get(canonical(child))
        if cached and cached[0] > time.time():
            return cached[1]
        response = self._ask(addresses, child, T_DNSKEY, dnssec=True)
        if response is None:
            raise Unvalidated("cannot fetch DNSKEY for %s" % child)
        keys = [r for r in response.answers if r.rtype == T_DNSKEY]
        sigs = [r for r in response.answers if r.rtype == T_RRSIG]
        if not keys:
            raise Unvalidated("no DNSKEY for signed zone %s" % child)
        self._verify_dnskey_set(keys, sigs, child)
        return keys

    def _check_keys_against_ds(self, child: str, keys: list[Record],
                               ds_records: list[Record]) -> None:
        supported = False
        for ds in ds_records:
            p = ds.parsed or {}
            if p.get("digestType") not in (DIGEST_SHA1, DIGEST_SHA256, DIGEST_SHA384):
                continue
            supported = True
            for key in keys:
                if key_tag(key.rdata) != p["keytag"]:
                    continue
                if ds_digest(child, key.rdata, p["digestType"]) == p["digest"]:
                    return
        if not supported:
            raise Unvalidated("only unsupported DS digests for %s" % child)
        raise Bogus("no DNSKEY of %s matches its DS" % child)

    def _matches_anchor(self, record: Record) -> bool:
        return self._anchor_match(record)


# Server-facing helpers -------------------------------------------------------

def answer_query(resolver: "Resolver", wire: bytes, *, max_udp: int = 1232) -> bytes:
    """Turn a client DNS message into a response, or SERVFAIL. No caching lies."""
    try:
        query = parse_message(wire)
    except ResolveError:
        return servfail(b"\x00\x00", None)
    if len(query.questions) != 1:
        return servfail(wire[:2], None, rcode=1)
    question = query.questions[0]
    try:
        answer = resolver.resolve(question.name, question.qtype)
    except ResolveError:
        resolver.stats["servfail"] += 1
        return servfail(wire[:2], question)
    response = encode_answer(wire[:2], question, answer)
    if len(response) > max_udp:
        flags = struct.unpack(">H", response[2:4])[0] | 0x0200
        response = response[:2] + struct.pack(">H", flags) + response[4:12]
    return response


def servfail(query_id: bytes, question: Question | None, *, rcode: int = 2) -> bytes:
    qid = struct.unpack(">H", query_id)[0] if len(query_id) >= 2 else 0
    header = struct.pack(">HHHHHH", qid, 0x8000 | 0x0080 | rcode, 1 if question else 0,
                         0, 0, 0)
    if question is None:
        return header
    return header + name_to_wire(question.name) + struct.pack(">HH", question.qtype, 1)


def encode_answer(query_id: bytes, question: Question, answer: "Answer") -> bytes:
    qid = struct.unpack(">H", query_id)[0]
    flags = 0x8000 | 0x0080 | (answer.rcode & 0x0F)  # QR, RA (we are the resolver)
    if answer.rcode == 0 and answer.records and answer.records[0].validated:
        flags |= 0x0020  # AD, only when the chain verified
    records = answer.records
    header = struct.pack(">HHHHHH", qid, flags, 1, len(records), 0, 0)
    body = name_to_wire(question.name) + struct.pack(">HH", question.qtype, 1)
    for record in records:
        rdata = canonical_rdata(record)
        body += (name_to_wire(record.name)
                 + struct.pack(">HHIH", record.rtype, 1, record.ttl, len(rdata)) + rdata)
    return header + body
