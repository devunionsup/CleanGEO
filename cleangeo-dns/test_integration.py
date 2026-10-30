"""Integration tests: config gates, key hygiene, browser config, client shape.

These cover the parts that are not covered by the unit suites: the refusal
behaviours that keep a mistake from becoming a leak.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import importlib.util as _ilu


def _helper():
    name = "cleango_dns_helper"
    if name in sys.modules:
        return sys.modules[name]
    spec = _ilu.spec_from_file_location(name, ROOT / "testfixtures.py")
    module = _ilu.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_H = _helper()
R, load = _H.R, _H.load

D = load("cleangeo_doh", "doh_server.py")
K = load("cleangeo_keys", "keys.py")
B = load("cleangeo_browser", "browser_integration.py")
S = load("cleangeo_server", "server.py")


def make_cert(directory: str, name: str = "dns.example.test"):
    cert, key = K.keygen(directory, name, days=30)
    return cert, key


class ServerConfigIntegration(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.cert, self.key = make_cert(self.directory)

    def args(self, **overrides):
        class Args:
            host = "127.0.0.1"
            port = 8443
            domain = "dns.example.test"
            cert = self.cert
            key = self.key
            cert_dir = ""
            client_ca = ""
            idle_timeout = 30.0
            no_dnssec = False
            insecure_http = False
        for name, value in overrides.items():
            setattr(Args, name, value)
        return Args()

    def test_check_passes_with_a_valid_pair(self):
        self.assertEqual(S.main(["check", "--cert", self.cert, "--key", self.key,
                                 "--domain", "dns.example.test"]), 0)

    def test_check_fails_without_a_certificate(self):
        self.assertEqual(S.main(["check", "--domain", "dns.example.test",
                                 "--insecure-http"]), 0)
        self.assertEqual(S.main(["check", "--domain", "dns.example.test"]), 1)

    def test_check_fails_without_a_domain(self):
        self.assertEqual(S.main(["check", "--cert", self.cert, "--key", self.key]), 1)

    def test_cert_dir_layout_is_resolved(self):
        directory = tempfile.mkdtemp()
        cert, key = make_cert(directory)
        os.replace(cert, os.path.join(directory, "fullchain.pem"))
        os.replace(key, os.path.join(directory, "privkey.pem"))
        resolved = K.chain_files(directory)
        self.assertTrue(resolved[0].endswith("fullchain.pem"))
        self.assertTrue(resolved[1].endswith("privkey.pem"))

    def test_cert_dir_without_key_is_refused(self):
        with self.assertRaises(K.KeyError_):
            K.chain_files(tempfile.mkdtemp())

    def test_expiry_is_reported(self):
        info = K.check_pair(self.cert, self.key)
        self.assertGreater(info.days_left, 0)
        self.assertLessEqual(info.days_left, 30)
        self.assertTrue(info.fresh_enough)

    def test_short_lived_certificate_is_flagged(self):
        directory = tempfile.mkdtemp()
        cert, key = K.keygen(directory, "short.example.test", days=2)
        info = K.check_pair(cert, key)
        self.assertFalse(info.fresh_enough)

    def test_mismatched_pair_is_refused(self):
        other_dir = tempfile.mkdtemp()
        _other_cert, other_key = K.keygen(other_dir, "other.example.test")
        with self.assertRaises(K.KeyError_) as caught:
            K.check_pair(self.cert, other_key)
        self.assertIn("do not form a valid pair", str(caught.exception))

    def test_group_readable_key_is_refused(self):
        os.chmod(self.key, 0o640)
        with self.assertRaises(K.KeyError_) as caught:
            K.check_pair(self.cert, self.key)
        self.assertIn("accessible to other users", str(caught.exception))

    def test_private_key_is_never_in_the_project(self):
        """Nothing in the repository may look like a private key."""
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.suffix in (".py", ".md", ".json", ".txt", ".mobileconfig",
                               ".html", ".pem"):
                text = path.read_text(errors="ignore")
                # Split so this test file does not match itself.
                for marker in ("BEGIN PRIVATE" + " KEY",
                               "BEGIN RSA PRIVATE" + " KEY",
                               "BEGIN EC PRIVATE" + " KEY"):
                    self.assertNotIn(marker, text, str(path))


class PinFileTests(unittest.TestCase):
    def setUp(self):
        import cstp
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)
        self.public = cstp.public_bytes(Ed25519PrivateKey.generate())
        self.path = os.path.join(tempfile.mkdtemp(), "pin.json")
        K.write_pin(self.path, self.public)

    def test_pin_roundtrip(self):
        pin = K.load_pin(self.path)
        self.assertEqual(pin.public_key, self.public)
        self.assertEqual(len(pin.public_key), 32)

    def test_pin_file_is_readable_but_holds_no_secret(self):
        mode = os.stat(self.path).st_mode & 0o777
        self.assertEqual(mode, 0o644)
        self.assertNotIn("PRIVATE", pathlib.Path(self.path).read_text())

    def test_bad_pin_length_is_refused(self):
        with open(self.path, "w") as handle:
            json.dump({"cstpServerKey": "00" * 16}, handle)
        with self.assertRaises(K.KeyError_):
            K.load_pin(self.path)

    def test_non_hex_pin_is_refused(self):
        with open(self.path, "w") as handle:
            json.dump({"cstpServerKey": "zz" * 32}, handle)
        with self.assertRaises(ValueError):
            K.load_pin(self.path)


class BrowserConfigTests(unittest.TestCase):
    def test_switches_carry_endpoint_and_secure_mode(self):
        config = B.ChromiumConfig("https://dns.example.test/dns-query")
        switches = config.switches()
        joined = " ".join(switches)
        self.assertIn("--dns-over-https-mode=secure", joined)
        self.assertIn("https://dns.example.test/dns-query", joined)
        self.assertIn("EXCLUDE dns.example.test", joined)

    def test_http_endpoint_is_refused(self):
        with self.assertRaises(B.IntegrationError):
            B.ChromiumConfig("http://dns.example.test/dns-query")

    def test_unknown_mode_is_refused(self):
        with self.assertRaises(B.IntegrationError):
            B.ChromiumConfig("https://dns.example.test/dns-query", "automatic-ish")

    def test_static_verification_passes(self):
        report = B.verify_config(B.ChromiumConfig())
        self.assertTrue(report["passed"], report["failures"])

    def test_policy_disables_prefetching(self):
        policy = B.ChromiumConfig().policy()
        self.assertIs(policy["DnsPrefetchingEnabled"], False)
        self.assertEqual(policy["DnsOverHttpsMode"], "secure")
        self.assertEqual(policy["NetworkPredictionOptions"], 2)

    def test_electron_snippet_uses_append_switch(self):
        snippet = B.ChromiumConfig().electron_snippet()
        self.assertIn("appendSwitch", snippet)
        self.assertIn("dns-over-https-templates", snippet)
        self.assertIn("before app.whenReady()", snippet)

    def test_live_check_reports_unavailable_rather_than_passing(self):
        result = B.verify_live(endpoint="https://127.0.0.1:9/dns-query",
                               timeout=2)
        self.assertFalse(result["passed"])
        self.assertIn("reason", result)


ROOT = pathlib.Path(__file__).resolve().parent


def source(name: str) -> str:
    return (ROOT / name).read_text()


class ClientShapeTests(unittest.TestCase):
    def test_client_refuses_plaintext_fallback(self):
        text = source("doh_client.py")
        self.assertIn("minimum_version = ssl.TLSVersion.TLSv1_3", text)
        self.assertIn('selected_alpn_protocol() != "h2"', text)
        # No port-53 path exists in the client at all.
        self.assertNotIn("SOCK_DGRAM", text)
        self.assertNotIn(", 53)", text)

    def test_resolver_has_no_public_upstream(self):
        text = source("resolver.py")
        for public_resolver in ("1.1.1.1", "8.8.8.8", "9.9.9.9", "94.140.14.14",
                                "dns.adguard", "cloudflare-dns", "dns.google"):
            self.assertNotIn(public_resolver, text)

    def test_server_never_logs_query_names(self):
        text = source("doh_server.py")
        self.assertNotIn("import logging", text)
        self.assertNotIn("logging.", text)
        # Nothing opens a file for writing: no log file, no cache file.
        for pattern in ('open("w', "write_text", "write_bytes"):
            self.assertNotIn(pattern, text)

    def test_probe_does_not_claim_anonymity(self):
        self.assertIn("does not make you anonymous", source("dns_probe.py"))


class DnssecRequirementTests(unittest.TestCase):
    def test_default_requires_dnssec(self):
        self.assertTrue(R.Resolver().require_dnssec)

    def test_disabling_is_explicit_and_reported(self):
        resolver = R.Resolver(require_dnssec=False)
        self.assertFalse(resolver.require_dnssec)
        self.assertEqual(len(resolver.anchors), 2)
        self.assertEqual(len(resolver.hints), 13)


if __name__ == "__main__":
    unittest.main(verbosity=2)
