"""Tests for the experimental CleanGEO protocol (cstp.py).

Every test runs a real handshake with real X25519/Ed25519/ChaCha20-Poly1305.
The clock is injected so the staleness bound can be tested deterministically.

Run: python test_cstp.py
"""
from __future__ import annotations

import pathlib
import sys
import unittest

_HERE = __import__("pathlib").Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import importlib.util as _ilu


def _helper():
    name = "cleango_dns_helper"
    if name in sys.modules:
        return sys.modules[name]
    spec = _ilu.spec_from_file_location(name, _HERE / "tests" / "_load.py")
    module = _ilu.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_H = _helper()
load = _H.load
C = load("cleangeo_cstp", "cstp.py")


class Clock:
    def __init__(self, value: float = 1_800_000_000.0):
        self.value = value

    def __call__(self) -> float:
        return self.value


def new_identity():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.generate()


def handshake(clock=None, *, server_key=None, client_pin=None, client_version=1):
    clock = clock or Clock()
    server_key = server_key or new_identity()
    pin = client_pin if client_pin is not None else C.public_bytes(server_key)
    client = C.Session(role="client", pinned_server_key=pin, now=clock)
    server = C.Session(role="server", identity=server_key, now=clock)
    hello = client.client_hello(version_max=client_version, now=clock())
    server_hello = server.server_accept_hello(hello)
    client_finish = client.client_accept_hello(server_hello)
    server_finish = server.server_finish(client_finish)
    client.client_finish(server_finish)
    return client, server


class HandshakeTests(unittest.TestCase):
    def test_both_sides_derive_the_same_keys(self):
        client, server = handshake()
        self.assertEqual(client.keys.c2s, server.keys.c2s)
        self.assertEqual(client.keys.s2c, server.keys.s2c)
        self.assertNotEqual(client.keys.c2s, client.keys.s2c)

    def test_transcript_matches(self):
        client, server = handshake()
        self.assertEqual(client.transcript, server.transcript)

    def test_both_sides_established(self):
        client, server = handshake()
        self.assertIs(client.state, C.State.ESTABLISHED)
        self.assertIs(server.state, C.State.ESTABLISHED)

    def test_requires_a_pinned_server_key(self):
        with self.assertRaises(ValueError):
            C.Session(role="client")

    def test_wrong_pin_is_refused_before_any_key_is_used(self):
        real_key = new_identity()
        attacker = new_identity()
        clock = Clock()
        client = C.Session(role="client", pinned_server_key=C.public_bytes(real_key),
                           now=clock)
        impostor = C.Session(role="server", identity=attacker, now=clock)
        hello = client.client_hello(now=clock())
        with self.assertRaises(C.CstpError) as caught:
            client.client_accept_hello(impostor.server_accept_hello(hello))
        self.assertEqual(caught.exception.code, C.ERR_PIN_MISMATCH)
        self.assertIsNone(client.keys)

    def test_forged_signature_is_refused(self):
        server_key = new_identity()
        clock = Clock()
        client = C.Session(role="client", pinned_server_key=C.public_bytes(server_key),
                           now=clock)
        server = C.Session(role="server", identity=server_key, now=clock)
        hello = client.client_hello(now=clock())
        server_hello = bytearray(server.server_accept_hello(hello))
        server_hello[-1] ^= 0x01  # corrupt the Ed25519 signature
        with self.assertRaises(C.CstpError) as caught:
            client.client_accept_hello(bytes(server_hello))
        self.assertEqual(caught.exception.code, C.ERR_BAD_SIGNATURE)

    def test_stale_server_hello_is_refused(self):
        server_key = new_identity()
        clock = Clock()
        client = C.Session(role="client", pinned_server_key=C.public_bytes(server_key),
                           now=clock)
        # The server builds its hello an hour in the past.
        server = C.Session(role="server", identity=server_key,
                           now=lambda: clock() - 3600)
        hello = client.client_hello(now=clock())
        server_hello = server.server_accept_hello(hello)
        with self.assertRaises(C.CstpError) as caught:
            client.client_accept_hello(server_hello)
        self.assertEqual(caught.exception.code, C.ERR_EXPIRED)

    def test_downgrade_is_refused_when_server_picks_lower_version(self):
        server_key = new_identity()
        clock = Clock()
        client = C.Session(role="client", pinned_server_key=C.public_bytes(server_key),
                           now=clock)
        server = C.Session(role="server", identity=server_key, now=clock)
        hello = bytearray(client.client_hello(now=clock()))
        hello[1] = 1  # offered version
        server_hello = bytearray(server.server_accept_hello(bytes(hello)))
        server_hello[1] = 0  # say the server picked an older version
        with self.assertRaises(C.CstpError) as caught:
            client.client_accept_hello(bytes(server_hello))
        self.assertEqual(caught.exception.code, C.ERR_DOWNGRADE)

    def test_unsupported_version_is_refused(self):
        clock = Clock()
        client = C.Session(role="client", pinned_server_key=b"\x00" * 32, now=clock)
        with self.assertRaises(C.CstpError) as caught:
            client.client_hello(version_max=99, now=clock())
        self.assertEqual(caught.exception.code, C.ERR_VERSION)

    def test_missing_key_confirmation_is_refused(self):
        client, _server = handshake()
        # A second call is out of state, and an empty message is not a
        # confirmation: both must fail closed rather than silently succeed.
        with self.assertRaises(C.CstpError) as caught:
            client.client_finish(b"\x13" + b"\x00" * 32)
        self.assertEqual(caught.exception.code, C.ERR_BAD_CONFIRMATION)

    def test_client_finish_requires_a_handshake_first(self):
        idle = C.Session(role="client", pinned_server_key=b"\x02" * 32, now=Clock())
        with self.assertRaises(C.CstpError) as caught:
            idle.client_finish(b"\x13" + b"\x00" * 32)
        self.assertEqual(caught.exception.code, C.ERR_STATE)


class FramingTests(unittest.TestCase):
    def setUp(self):
        self.client, self.server = handshake()

    def test_data_roundtrip(self):
        self.assertEqual(self.server.open(self.client.seal(b"query bytes")),
                         b"query bytes")

    def test_directions_have_independent_counters(self):
        self.assertEqual(self.server.open(self.client.seal(b"one")), b"one")
        self.assertEqual(self.client.open(self.server.seal(b"two")), b"two")

    def test_tampered_ciphertext_is_refused(self):
        frame = bytearray(self.client.seal(b"secret"))
        frame[-1] ^= 0x01
        with self.assertRaises(C.CstpError) as caught:
            self.server.open(bytes(frame))
        self.assertEqual(caught.exception.code, C.ERR_BAD_FRAME)

    def test_tampered_header_is_refused(self):
        frame = bytearray(self.client.seal(b"secret"))
        frame[10] ^= 0x01  # a counter byte, which the AEAD authenticates
        # The counter is authenticated but not encrypted, so a flipped counter is
        # caught by the tag check; either way the frame must not be accepted.
        with self.assertRaises(C.CstpError) as caught:
            self.server.open(bytes(frame))
        self.assertIn(caught.exception.code, (C.ERR_REPLAY, C.ERR_BAD_FRAME))

    def test_replay_is_refused(self):
        frame = self.client.seal(b"once")
        self.assertEqual(self.server.open(frame), b"once")
        with self.assertRaises(C.CstpError) as caught:
            self.server.open(frame)
        self.assertEqual(caught.exception.code, C.ERR_REPLAY)

    def test_reordering_within_the_window_is_accepted(self):
        frames = [self.client.seal(b"f%d" % index) for index in range(4)]
        self.assertEqual(self.server.open(frames[0]), b"f0")
        self.assertEqual(self.server.open(frames[3]), b"f3")
        self.assertEqual(self.server.open(frames[1]), b"f1")
        self.assertEqual(self.server.open(frames[2]), b"f2")

    def test_future_counter_with_a_valid_tag_advances_the_window(self):
        # Counters are authenticated, so an attacker cannot forge a high one; but
        # a legitimate jump must work and must not block the skipped frames
        # while they are still inside the window.
        frames = [self.client.seal(b"g%d" % index) for index in range(3)]
        self.assertEqual(self.server.open(frames[2]), b"g2")
        self.assertEqual(self.server.open(frames[0]), b"g0")
        self.assertEqual(self.server.open(frames[1]), b"g1")

    def test_frame_from_another_session_is_refused(self):
        other_client, other_server = handshake()
        with self.assertRaises(C.CstpError) as caught:
            other_server.open(self.client.seal(b"wrong session"))
        self.assertIn(caught.exception.code, (C.ERR_BAD_FRAME, C.ERR_REPLAY))
        del other_client

    def test_oversized_payload_is_refused(self):
        with self.assertRaises(C.CstpError) as caught:
            self.client.seal(b"x" * (C.MAX_FRAME + 1))
        self.assertEqual(caught.exception.code, C.ERR_TOO_LARGE)

    def test_send_before_handshake_is_refused(self):
        idle = C.Session(role="client", pinned_server_key=b"\x01" * 32, now=Clock())
        with self.assertRaises(C.CstpError) as caught:
            idle.seal(b"too early")
        self.assertEqual(caught.exception.code, C.ERR_STATE)


class RotationTests(unittest.TestCase):
    def test_rekey_changes_keys_and_resets_counters(self):
        client, server = handshake()
        first_epoch = client.keys.epoch
        before = client.keys.c2s
        client._rekey()
        server._rekey()
        self.assertEqual(client.keys.c2s, server.keys.c2s)
        self.assertNotEqual(client.keys.c2s, before)
        self.assertEqual(client.keys.epoch, first_epoch + 1)

    def test_rekey_happens_at_the_configured_threshold(self):
        client, server = handshake()
        client.rekey_after = 2
        server.rekey_after = 2
        server.open(client.seal(b"a"))
        server.open(client.seal(b"b"))
        server._rekey()  # the peer ratchets when its own counter reaches the bound
        frame = client.seal(b"c")  # client-side ratchet
        self.assertEqual(client.keys.epoch, 1)
        self.assertEqual(server.open(frame), b"c")

    def test_old_epoch_frames_are_not_reusable(self):
        client, server = handshake()
        stale = client.seal(b"old epoch")
        client._rekey()
        server._rekey()
        with self.assertRaises(C.CstpError) as caught:
            server.open(stale)
        self.assertEqual(caught.exception.code, C.ERR_REPLAY)


class LifetimelessSanityTests(unittest.TestCase):
    def test_close_moves_to_closed_and_drops_keys(self):
        client, _server = handshake()
        client.close("done")
        self.assertIs(client.state, C.State.CLOSED)
        self.assertIsNone(client.keys)

    def test_error_names_are_documented(self):
        for code, name in C.ERROR_NAMES.items():
            self.assertTrue(name, "error 0x%02x has no name" % code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
