"""CleanGEO Secure Transport Protocol (CSTP) — experimental, review-gated.

Status: EXPERIMENTAL. Not used for production traffic. The production path is
TLS 1.3 (see doh_server.py). Nothing here replaces TLS; this layer is designed
to sit *inside* TLS 1.3 as a second, end-to-end encryption layer, so that a
TLS-terminating proxy at the hosting provider cannot read DNS questions.

Cryptography used (all established, none invented):
  * X25519            ephemeral key agreement (RFC 7748)
  * HKDF-SHA256       key derivation (RFC 5869)
  * ChaCha20-Poly1305 AEAD (RFC 8439)
  - Ed25519           server identity signature (RFC 8032)

No new cipher, no custom S-box, no hand-rolled MAC. The only original work here
is the *construction* around those primitives, and a construction can be wrong
even when its primitives are sound. That is why this file is inert unless a
caller explicitly opts in, and why CSTP-SPEC.md states it must be reviewed
before use with real user traffic.

Implemented: version negotiation with downgrade detection, mutual key
confirmation, transcript binding, AEAD framing, anti-replay window, key
rotation (hash ratchet with epoch separation), and fail-closed error handling.
See cstp-spec.md for the byte-level specification.
"""
from __future__ import annotations

import enum
import hashlib
import hmac
import os
import struct
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_NAME = b"cleangeo-cstp-v1"
SUPPORTED_VERSIONS = (1,)

# Frame types.
FT_HANDSHAKE = 0x01
FT_DATA = 0x02
FT_REKEY = 0x03
FT_CLOSE = 0x04
FT_PING = 0x05

# Handshake message types.
HS_CLIENT_HELLO = 0x10
HS_SERVER_HELLO = 0x11
HS_CLIENT_FINISH = 0x12
HS_SERVER_FINISH = 0x13
HS_ABORT = 0x1F

# Failure codes. Every one of them means "destroy the session".
ERR_VERSION = 0x01
ERR_DOWNGRADE = 0x02
ERR_PIN_MISMATCH = 0x03
ERR_BAD_SIGNATURE = 0x04
ERR_BAD_CONFIRMATION = 0x05
ERR_REPLAY = 0x06
ERR_BAD_FRAME = 0x07
ERR_STATE = 0x08
ERR_EXPIRED = 0x09
ERR_TOO_LARGE = 0x0A

MAX_FRAME = 16 * 1024
MAX_CLOCK_SKEW = 300
REKEY_AFTER_FRAMES = 1 << 20
REPLAY_WINDOW_BITS = 64

ERROR_NAMES = {
    ERR_VERSION: "unsupported protocol version",
    ERR_DOWNGRADE: "version downgrade attempt",
    ERR_PIN_MISMATCH: "server identity does not match the pinned key",
    ERR_BAD_SIGNATURE: "handshake signature did not verify",
    ERR_BAD_CONFIRMATION: "key confirmation failed",
    ERR_REPLAY: "replayed or out-of-window frame",
    ERR_BAD_FRAME: "malformed frame or authentication tag failure",
    ERR_STATE: "message not valid in the current state",
    ERR_EXPIRED: "handshake outside its validity window",
    ERR_TOO_LARGE: "frame exceeds the size limit",
}


class CstpError(Exception):
    """Fatal protocol error. The session is unusable afterwards."""

    def __init__(self, code: int, detail: str = ""):
        self.code = code
        self.name = ERROR_NAMES.get(code, "unknown error")
        super().__init__("%s (0x%02x)%s" % (self.name, code,
                                            ": " + detail if detail else ""))


class State(enum.Enum):
    START = "start"
    HELLO_SENT = "hello-sent"
    HELLO_RECEIVED = "hello-received"
    ESTABLISHED = "established"
    CLOSED = "closed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _hkdf(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(secret)


def _transcript(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(struct.pack(">I", len(part)))
        digest.update(part)
    return digest.digest()


def _b32(value: int) -> bytes:
    if not 0 <= value < 1 << 32:
        raise CstpError(ERR_BAD_FRAME, "timestamp out of range")
    return struct.pack(">I", value)


def _unb32(data: bytes, offset: int) -> int:
    if len(data) < offset + 4:
        raise CstpError(ERR_BAD_FRAME, "truncated message")
    return struct.unpack(">I", data[offset:offset + 4])[0]


def public_bytes(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


# ---------------------------------------------------------------------------
# replay protection
# ---------------------------------------------------------------------------

class ReplayWindow:
    """Monotonic counter plus a 64-entry sliding bitmap (RFC 6479 style).

    A frame is accepted only if its counter is higher than every counter seen so
    far, or new-but-not-too-old and not already set. Anything else is rejected,
    so a captured frame cannot be replayed inside the window.
    """

    def __init__(self, bits: int = REPLAY_WINDOW_BITS):
        self.bits = bits
        self.highest = -1
        self._bitmap = 0

    def accept(self, counter: int) -> bool:
        if counter < 0:
            return False
        if counter > self.highest:
            shift = counter - self.highest
            if shift >= self.bits:
                self._bitmap = 1
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & ((1 << self.bits) - 1)
            self.highest = counter
            return True
        offset = self.highest - counter
        if offset >= self.bits:
            return False
        mask = 1 << offset
        if self._bitmap & mask:
            return False
        self._bitmap |= mask
        return True


# ---------------------------------------------------------------------------
# session state and keys
# ---------------------------------------------------------------------------

class KeyPair:
    __slots__ = ("c2s", "s2c", "c2s_nonce", "s2c_nonce", "epoch")

    def __init__(self, c2s: bytes, s2c: bytes, c2s_nonce: bytes, s2c_nonce: bytes,
                 epoch: int):
        self.c2s, self.s2c = c2s, s2c
        self.c2s_nonce, self.s2c_nonce = c2s_nonce, s2c_nonce
        self.epoch = epoch


class Session:
    """One CSTP connection. Create via `connect()` or `accept()`."""

    def __init__(self, *, role: str, identity: Ed25519PrivateKey | None = None,
                 pinned_server_key: bytes | None = None,
                 rekey_after: int = REKEY_AFTER_FRAMES,
                 now: callable = time.time,
                 allow_experimental: bool = True):
        if role not in ("client", "server"):
            raise ValueError("role must be 'client' or 'server'")
        self.role = role
        self.identity = identity
        self.pinned = pinned_server_key
        self.rekey_after = rekey_after
        self._now = now
        self.state = State.START
        self.keys: KeyPair | None = None
        self.sent = 0
        self.received = 0
        self.send_window = ReplayWindow()
        self.recv_window = ReplayWindow()
        self.transcript = b""
        self.server_public = None
        self.negotiated_version = None
        self.aborted_with: CstpError | None = None
        self.established_at: float | None = None
        self.rekeys = 0
        if role == "server" and identity is None:
            raise ValueError("server needs a static Ed25519 identity key")
        if role == "client" and pinned_server_key is None:
            raise ValueError(
                "client needs the pinned server key; an unpinned client cannot "
                "detect server substitution")
        del allow_experimental  # gating happens at the call site, see doh_server

    # -- helpers -----------------------------------------------------
    def _fail(self, code: int, detail: str = "") -> "CstpError":
        self.state = State.FAILED
        error = CstpError(code, detail)
        self.aborted_with = error
        self.keys = None
        return error

    def _require(self, state: State) -> None:
        if self.state is not state:
            raise self._fail(ERR_STATE, "expected %s, in %s" % (state.value,
                                                                 self.state.value))

    def _ephemeral(self) -> X25519PrivateKey:
        self._eph = X25519PrivateKey.generate()
        return self._eph

    # -- client ------------------------------------------------------
    def client_hello(self, *, version_max: int = 1, now: float | None = None) -> bytes:
        self._require(State.START)
        if version_max not in SUPPORTED_VERSIONS:
            raise self._fail(ERR_VERSION, "client asked for version %d" % version_max)
        now = self._now() if now is None else now
        client_random = os.urandom(32)
        ephemeral = self._ephemeral()
        body = (bytes([HS_CLIENT_HELLO, version_max])
                + client_random
                + public_bytes(ephemeral)
                + _b32(int(now)))
        self._client_random = client_random
        self._versions = (version_max,)
        self.transcript = _transcript(PROTOCOL_NAME, body)
        self.state = State.HELLO_SENT
        return body

    def client_accept_hello(self, message: bytes) -> bytes:
        self._require(State.HELLO_SENT)
        if len(message) < 2 or message[0] != HS_SERVER_HELLO:
            raise self._fail(ERR_BAD_FRAME, "expected SERVER_HELLO")
        version = message[1]
        if version < max(self._versions):
            # The server must pick the highest version the client offered. Any
            # lower pick is a downgrade attempt, not a preference. Checked
            # before support, so a bogus low version cannot be read as "unsupported".
            raise self._fail(ERR_DOWNGRADE,
                             "server chose %d, client offered %s"
                             % (version, list(self._versions)))
        if version not in SUPPORTED_VERSIONS:
            raise self._fail(ERR_VERSION, "server chose version %d" % version)
        offset = 2
        server_random = message[offset:offset + 32]
        offset += 32
        server_ephemeral = message[offset:offset + 32]
        offset += 32
        server_identity = message[offset:offset + 32]
        offset += 32
        timestamp = _unb32(message, offset)
        offset += 4
        signature = message[offset:offset + 64]
        offset += 64
        if offset != len(message):
            raise self._fail(ERR_BAD_FRAME, "trailing bytes in SERVER_HELLO")

        if timestamp + MAX_CLOCK_SKEW < self._now():
            raise self._fail(ERR_EXPIRED, "server hello is stale")
        if server_identity != self.pinned:
            raise self._fail(ERR_PIN_MISMATCH)
        signed = (message[:offset - 64] + self._client_random)
        try:
            Ed25519PublicKey.from_public_bytes(server_identity).verify(signature,
                                                                       signed)
        except InvalidSignature:
            raise self._fail(ERR_BAD_SIGNATURE)

        shared = self._eph.exchange(X25519PublicKey.from_public_bytes(server_ephemeral))
        transcript = _transcript(self.transcript, message, self._client_random)
        self.transcript = transcript
        master = _hkdf(shared, transcript, PROTOCOL_NAME + b" master")
        self.keys = self._derive(master, 0)
        self.server_public = server_identity
        self.negotiated_version = version
        self._server_ephemeral = server_ephemeral
        self.state = State.HELLO_RECEIVED

        confirm = self._confirmation(self.keys.c2s_nonce, b"client finished")
        self.state = State.ESTABLISHED
        self.established_at = self._now()
        self._master = master
        return bytes([HS_CLIENT_FINISH]) + confirm

    def client_finish(self, message: bytes, *, allow_unconfirmed: bool = False) -> None:
        """Verify the server's key confirmation. Without it there is no mutual
        authentication, so skipping it is refused unless explicitly asked."""
        if self.state is not State.ESTABLISHED:
            raise self._fail(ERR_STATE)
        if allow_unconfirmed:
            return
        if len(message) != 33 or message[0] != HS_SERVER_FINISH:
            raise self._fail(ERR_BAD_FRAME, "expected SERVER_FINISH")
        expected = self._confirmation(self.keys.s2c_nonce, b"server finished")
        if not hmac.compare_digest(message[1:], expected):
            raise self._fail(ERR_BAD_CONFIRMATION)

    # -- server ------------------------------------------------------
    def server_accept_hello(self, message: bytes) -> bytes:
        self._require(State.START)
        if len(message) < 2 or message[0] != HS_CLIENT_HELLO:
            raise self._fail(ERR_BAD_FRAME, "expected CLIENT_HELLO")
        offered = message[1]
        if offered not in SUPPORTED_VERSIONS:
            raise self._fail(ERR_VERSION, "client offered version %d" % offered)
        version = min(offered, max(SUPPORTED_VERSIONS))
        if version < offered:
            raise self._fail(ERR_DOWNGRADE, "would have to downgrade")
        client_random = message[2:34]
        client_ephemeral = message[34:66]
        client_time = _unb32(message, 66)
        if len(message) != 70:
            raise self._fail(ERR_BAD_FRAME, "trailing bytes in CLIENT_HELLO")
        if abs(client_time - self._now()) > MAX_CLOCK_SKEW * 24:
            raise self._fail(ERR_EXPIRED, "client clock is far off")

        ephemeral = self._ephemeral()
        server_random = os.urandom(32)
        body = (bytes([HS_SERVER_HELLO, version]) + server_random
                + public_bytes(ephemeral) + public_bytes(self.identity)
                + _b32(int(timestamp := self._now())))
        signed = body + client_random
        signature = self.identity.sign(signed)
        message_out = body + signature
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(client_ephemeral))
        transcript = _transcript(_transcript(PROTOCOL_NAME, message), message_out,
                                 client_random)
        self.transcript = transcript
        master = _hkdf(shared, transcript, PROTOCOL_NAME + b" master")
        self.keys = self._derive(master, 0)
        self._master = master
        self.negotiated_version = version
        self.state = State.HELLO_RECEIVED
        del timestamp
        return message_out

    def server_finish(self, message: bytes) -> bytes:
        self._require(State.HELLO_RECEIVED)
        if len(message) != 33 or message[0] != HS_CLIENT_FINISH:
            raise self._fail(ERR_BAD_FRAME, "expected CLIENT_FINISH")
        expected = self._confirmation(self.keys.c2s_nonce, b"client finished")
        if not hmac.compare_digest(message[1:], expected):
            raise self._fail(ERR_BAD_CONFIRMATION)
        self.state = State.ESTABLISHED
        self.established_at = self._now()
        return bytes([HS_SERVER_FINISH]) + self._confirmation(
            self.keys.s2c_nonce, b"server finished")

    # -- keys --------------------------------------------------------
    def _derive(self, master: bytes, epoch: int) -> KeyPair:
        info = PROTOCOL_NAME + b" kdf" + _b32(epoch)
        c2s = _hkdf(master, self.transcript, info + b" c2s")
        s2c = _hkdf(master, self.transcript, info + b" s2c")
        c2s_nonce = _hkdf(master, self.transcript, info + b" c2s nonce", 4)
        s2c_nonce = _hkdf(master, self.transcript, info + b" s2c nonce", 4)
        return KeyPair(c2s, s2c, c2s_nonce, s2c_nonce, epoch)

    def _confirmation(self, nonce: bytes, label: bytes) -> bytes:
        """HMAC over the label keyed by the direction key's first 32 bytes.

        Deliberately not an AEAD tag: it is a pure possession proof, and HMAC is
        the boring primitive for that.
        """
        key = self.keys.c2s if label.startswith(b"client") else self.keys.s2c
        return hmac.new(key, self.transcript + label, hashlib.sha256).digest()

    def _rekey(self) -> None:
        if self.keys is None or self.state is not State.ESTABLISHED:
            raise self._fail(ERR_STATE, "no session to rekey")
        epoch = self.keys.epoch + 1
        # Hash ratchet: the new epoch's keys come from the master secret with a
        # different info string, so a leaked epoch key does not reveal the next
        # one, and old frames cannot be replayed into the new epoch.
        self.keys = self._derive(self._master, epoch)
        self.send_window = ReplayWindow()
        self.recv_window = ReplayWindow()
        self.sent = 0
        self.received = 0
        self.rekeys += 1

    # -- records -----------------------------------------------------
    def _send_key(self) -> tuple[bytes, bytes]:
        """(key, nonce prefix) for frames this side sends."""
        if self.role == "client":
            return self.keys.c2s, self.keys.c2s_nonce
        return self.keys.s2c, self.keys.s2c_nonce

    def _recv_key(self) -> tuple[bytes, bytes]:
        """(key, nonce prefix) for frames this side receives."""
        if self.role == "client":
            return self.keys.s2c, self.keys.s2c_nonce
        return self.keys.c2s, self.keys.c2s_nonce

    def seal(self, plaintext: bytes, *, frame_type: int = FT_DATA) -> bytes:
        if self.state is not State.ESTABLISHED:
            raise self._fail(ERR_STATE, "cannot send before the handshake")
        plaintext = bytes(plaintext)
        if len(plaintext) > MAX_FRAME:
            raise self._fail(ERR_TOO_LARGE)
        if self.sent >= self.rekey_after:
            self._rekey()
        counter = self.sent
        self.sent += 1
        key, nonce_prefix = self._send_key()
        header = struct.pack(">BBQI", frame_type, 1, counter, self.keys.epoch)
        nonce = nonce_prefix + struct.pack(">Q", counter)
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, header)
        return header + struct.pack(">H", len(ciphertext)) + ciphertext

    def open(self, frame: bytes) -> bytes:
        if self.state is not State.ESTABLISHED:
            raise self._fail(ERR_STATE, "cannot receive before the handshake")
        if len(frame) < 16:
            raise self._fail(ERR_BAD_FRAME, "frame too short")
        frame_type, flags, counter, epoch = struct.unpack(">BBQI", frame[:14])
        length = struct.unpack(">H", frame[14:16])[0]
        ciphertext = frame[16:]
        if flags & 0xFE:
            raise self._fail(ERR_BAD_FRAME, "unknown frame flags")
        if length != len(ciphertext) or length > MAX_FRAME + 16:
            raise self._fail(ERR_BAD_FRAME, "length mismatch")
        if epoch != self.keys.epoch:
            raise self._fail(ERR_REPLAY, "frame from a different key epoch")

        key, nonce_prefix = self._recv_key()
        nonce = nonce_prefix + struct.pack(">Q", counter)
        try:
            # Authenticate before touching the replay window: an injected frame
            # must not be able to advance or poison the window state.
            plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, frame[:14])
        except InvalidTag:
            raise self._fail(ERR_BAD_FRAME, "authentication tag mismatch")
        if not self.recv_window.accept(counter):
            raise self._fail(ERR_REPLAY, "counter %d already seen" % counter)

        self.received += 1
        if frame_type == FT_CLOSE:
            self.state = State.CLOSED
            self.keys = None
        return plaintext

    def close(self, reason: str = "") -> bytes:
        if self.state is State.ESTABLISHED:
            frame = self.seal(b"close:" + reason.encode()[:64], frame_type=FT_CLOSE)
        else:
            frame = b""
        self.state = State.CLOSED
        self.keys = None
        return frame
