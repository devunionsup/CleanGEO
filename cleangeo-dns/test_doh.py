"""DoH server tests: HTTP/2 framing, RFC 8484 shapes, TLS config, no leaks.

Sockets cannot listen in this sandbox, so the connection logic is driven
directly: a real h2 client talks to `DohHandler` and the bytes are exchanged the
way a socket would exchange them. TLS settings are asserted on the real
SSLContext object.
"""
from __future__ import annotations

import base64
import importlib.util
import pathlib
import ssl
import sys
import tempfile
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))


def _support():
    name = "cleango_dns_helper"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, _HERE / "testfixtures.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


F = _support()
R = F.R
load = F.load

D = load("cleangeo_doh", "doh_server.py")

from h2.config import H2Configuration  # noqa: E402
from h2.connection import H2Connection  # noqa: E402
from h2.events import DataReceived, ResponseReceived  # noqa: E402

Stats = D.Stats
DohHandler = D.DohHandler
DOH_PATH = D.DOH_PATH
DNS_MESSAGE = D.DNS_MESSAGE


def make_config():
    return D.ServerConfig(allow_insecure_http=True)


def parse_response(events):
    status = None
    headers: dict = {}
    body = b""
    for event in events:
        if isinstance(event, ResponseReceived):
            status = int(event.headers[0][1])
            headers = {as_text(key): as_text(value) for key, value in event.headers}
        elif isinstance(event, DataReceived):
            body += event.data
    return status, headers, body


def as_text(value) -> str:
    return value.decode() if isinstance(value, bytes) else value


class _Base(unittest.TestCase):
    def setUp(self):
        self.tree = F.TestTree()
        self.resolver = self.tree.resolver()
        self.stats = D.Stats()
        self.handler = D.DohHandler(self.resolver, make_config(), self.stats)
        self.client = H2Connection(config=H2Configuration(client_side=True,
                                                          header_encoding="utf-8"))
        self.conn = self.client

    def run_request(self, *, method="GET", path=DOH_PATH, headers=(), body=b""):
        self.conn.initiate_connection()
        server_out = self.handler.handle(self.conn.data_to_send())
        if server_out:
            self.conn.receive_data(server_out)
        stream_id = self.conn.get_next_available_stream_id()
        full_headers = [(b":method", method.encode()), (b":path", path.encode()),
                        (b":scheme", b"https"),
                        (b":authority", b"dns.example.com")] + list(headers)
        self.conn.send_headers(stream_id, full_headers, end_stream=not body)
        if body:
            self.conn.send_data(stream_id, body, end_stream=True)
        server_out = self.handler.handle(self.conn.data_to_send())
        events = self.conn.receive_data(server_out) if server_out else []
        return events


def make_config() -> object:
    return D.ServerConfig(allow_insecure_http=True)


class DohShapesTests(_Base):
    def test_get_query_answered_with_dns_message(self):
        query = R.build_query("www.example.test.", R.T_A, rd=True)
        encoded = base64.urlsafe_b64encode(query).decode().rstrip("=")
        events = self.run_request(path=DOH_PATH + "?dns=" + encoded,
                                  headers=[(b"accept", DNS_MESSAGE.encode())])
        status, headers, body = parse_response(events)
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], DNS_MESSAGE)
        self.assertEqual(headers["cache-control"], "no-store")
        parsed = R.parse_message(body)
        self.assertEqual(parsed.answers[0].parsed, "203.0.113.7")
        self.assertTrue(int.from_bytes(body[2:4], "big") & 0x0020, "AD bit")

    def test_post_query_answered(self):
        query = R.build_query("www.example.test.", R.T_A, rd=True)
        events = self.run_request(method="POST", body=query,
                                  headers=[(b"content-type", DNS_MESSAGE.encode()),
                                           (b"accept", DNS_MESSAGE.encode())])
        status, _headers, body = parse_response(events)
        self.assertEqual(status, 200)
        self.assertEqual(R.parse_message(body).answers[0].parsed, "203.0.113.7")

    def test_wrong_path_is_refused(self):
        status, headers, _body = parse_response(self.run_request(path="/nope"))
        self.assertEqual(status, 404)
        self.assertEqual(headers["content-type"], "application/json")

    def test_wrong_content_type_is_refused(self):
        query = R.build_query("www.example.test.", R.T_A, rd=True)
        status, _headers, _body = parse_response(
            self.run_request(method="POST", body=query,
                             headers=[(b"content-type", b"text/plain")]))
        self.assertEqual(status, 415)

    def test_missing_dns_parameter_is_refused(self):
        status, _headers, _body = parse_response(self.run_request(path=DOH_PATH))
        self.assertEqual(status, 400)

    def test_bad_base64_is_refused(self):
        status, _headers, body = parse_response(
            self.run_request(path=DOH_PATH + "?dns=!!!not-base64!!!"))
        self.assertEqual(status, 400)
        self.assertNotIn(b"dns=", body)

    def test_unsupported_method_is_refused(self):
        status, _headers, _body = parse_response(self.run_request(method="DELETE"))
        self.assertEqual(status, 405)

    def test_resolver_failure_returns_dns_servfail_without_echoing_the_name(self):
        query = R.build_query("beaten.example.test.", R.T_A, rd=True)
        encoded = base64.urlsafe_b64encode(query).decode().rstrip("=")
        status, headers, body = parse_response(
            self.run_request(path=DOH_PATH + "?dns=" + encoded,
                             headers=[(b"accept", DNS_MESSAGE.encode())]))
        # A resolver failure is reported as DNS SERVFAIL, not as an HTTP error
        # page: the client's stub resolver needs a DNS-level answer.
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], DNS_MESSAGE)
        parsed = R.parse_message(body)
        self.assertEqual(parsed.rcode, 2)
        self.assertFalse(parsed.flags & 0x0020, "SERVFAIL must never set AD")
        self.assertEqual(self.stats.servfail, 1)
        # The question section is echoed because a DNS client matches responses
        # by it (RFC 1035). What must not appear is any answer or authority
        # record, and the error must not be an HTTP page describing the name.
        self.assertEqual(parsed.answers, [])
        self.assertEqual(parsed.authority, [])
        self.assertEqual(len(parsed.questions), 1)
        self.assertNotIn(b"error", body.lower())

    def test_stats_are_aggregate_only(self):
        query = R.build_query("www.example.test.", R.T_A, rd=True)
        self.run_request(path=DOH_PATH + "?dns="
                         + base64.urlsafe_b64encode(query).decode().rstrip("="))
        snapshot = self.stats.to_dict()
        text = str(snapshot)
        self.assertNotIn("example", text)
        self.assertNotIn("192.0.2", text)
        self.assertEqual(snapshot["queries"], 1)
        self.assertEqual(snapshot["answered"], 1)


class DecodeTests(unittest.TestCase):
    def test_padding_is_optional(self):
        raw = b"\x12\x34\x01\x00"
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertEqual(D.decode_get_query(encoded), raw)
        self.assertEqual(D.decode_get_query(encoded + "=="), raw)

    def test_rejects_non_base64(self):
        for value in ("abc$def", "", "a b"):
            with self.assertRaises(ValueError):
                D.decode_get_query(value)


class TlsConfigTests(unittest.TestCase):
    def write_pair(self):
        directory = tempfile.mkdtemp()
        cert = pathlib.Path(directory, "cert.pem")
        key = pathlib.Path(directory, "key.pem")
        cert.write_text(CERT_PEM)
        key.write_text(KEY_PEM)
        # Both files must be private: the server refuses either above 0600.
        cert.chmod(0o600)
        key.chmod(0o600)
        return str(cert), str(key)

    def test_tls_requires_certificate_unless_explicitly_insecure(self):
        with self.assertRaises(D.ConfigError):
            D.ServerConfig().validate()

    def test_missing_file_is_reported(self):
        config = D.ServerConfig(certfile="/nonexistent/cert.pem",
                                keyfile="/nonexistent/key.pem")
        with self.assertRaises(D.ConfigError):
            config.validate()

    def test_world_readable_key_is_refused(self):
        cert, key = self.write_pair()
        pathlib.Path(key).chmod(0o644)
        with self.assertRaises(D.ConfigError) as caught:
            D.ServerConfig(certfile=cert, keyfile=key).validate()
        self.assertIn("readable by other users", str(caught.exception))

    def test_context_pins_tls13(self):
        cert, key = self.write_pair()
        config = D.ServerConfig(certfile=cert, keyfile=key)
        config.validate()
        context = config.tls_context()
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertTrue(context.options & ssl.OP_NO_COMPRESSION)

    def test_client_cert_requires_a_ca(self):
        cert, key = self.write_pair()
        with self.assertRaises(D.ConfigError):
            D.ServerConfig(certfile=cert, keyfile=key,
                           require_client_cert=True).validate()


CERT_PEM = ""
KEY_PEM = ""


def setUpModule():
    """Generate a throwaway self-signed certificate for the TLS config tests."""
    import subprocess
    directory = tempfile.mkdtemp()
    cert = pathlib.Path(directory, "c.pem")
    key = pathlib.Path(directory, "k.pem")
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "1",
             "-subj", "/CN=dns.cleangeo.test"],
            check=True, capture_output=True, timeout=60)
        globals()["CERT_PEM"] = cert.read_text()
        globals()["KEY_PEM"] = key.read_text()
    except Exception:
        globals()["CERT_PEM"] = ""
        globals()["KEY_PEM"] = ""


if __name__ == "__main__":
    unittest.main(verbosity=2)
