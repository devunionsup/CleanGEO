"""CleanGEO DoH (and DoT) front end for the private resolver.

Production transport is TLS 1.3. That is the security boundary for the client
leg; nothing experimental is used on this path.

Design decisions worth knowing:

* HTTP/2 is mandatory for DoH (RFC 8484 5.1 requires at least HTTP/2 for the
  "application/dns-message" media type). This implementation speaks HTTP/2 via
  the `h2` package and shuts the connection down rather than pretending an
  HTTP/1.1 request is DoH.
* `?dns=` base64url GET and POST bodies are both supported, per RFC 8484 4.1.
* Queries are answered from memory only: there is no log of questions, no
  request log at all, and nothing is written to disk. The only counters are
  aggregate numbers.
* `/dns-query` requires an allowed media type, a well-formed DNS message, and a
  single question. Anything else gets a minimal HTTP error, without echoing the
  query.
* The TLS context pins TLS 1.3 minimum, so a downgrade to TLS 1.2 is not a
  configuration option that can be flipped by accident.
"""
from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (ConnectionTerminated, DataReceived, RequestReceived,
                       StreamEnded, StreamReset, WindowUpdated)
from h2.exceptions import H2Error, ProtocolError

from tests._load import R

DOH_PATH = "/dns-query"
DNS_MESSAGE = "application/dns-message"
MAX_BODY = 4096
MAX_CONCURRENT_STREAMS = 100


class ConfigError(Exception):
    """Configuration that cannot safely serve traffic."""


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 443
    certfile: str = ""
    keyfile: str = ""
    cert_dir: str = ""
    allow_insecure_http: bool = False   # dev only, refuses unless explicit
    min_tls_version: int = ssl.TLSVersion.TLSv1_3
    require_client_cert: bool = False
    client_ca: str = ""
    idle_timeout: float = 30.0
    max_streams: int = MAX_CONCURRENT_STREAMS

    def validate(self) -> None:
        if not self.allow_insecure_http:
            if not self.certfile or not self.keyfile:
                raise ConfigError(
                    "TLS certificate and key are required; set allow_insecure_http "
                    "only for local development")
            for path in (self.certfile, self.keyfile):
                if not os.path.isfile(path):
                    raise ConfigError("missing TLS file: %s" % path)
            # Only the private key is a secret. The certificate is public by
            # definition and is normally readable by every user on the host.
            key_mode = os.stat(self.keyfile).st_mode & 0o777
            if key_mode & 0o077:
                raise ConfigError(
                    "%s is readable by other users (mode %o); chmod 600 it"
                    % (self.keyfile, key_mode))
            if self.require_client_cert and not self.client_ca:
                raise ConfigError("require_client_cert needs client_ca")
            if self.require_client_cert and not os.path.isfile(self.client_ca):
                raise ConfigError("missing client CA file: %s" % self.client_ca)
        if not 0 < self.port < 65536:
            raise ConfigError("port out of range")

    def tls_context(self) -> ssl.SSLContext | None:
        if self.allow_insecure_http:
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = self.min_tls_version
        # TLS 1.3 suites are chosen by OpenSSL's defaults, which are all AEAD.
        # 1.2 ciphers are set only so that a misconfiguration is visible.
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
        context.options |= ssl.OP_NO_COMPRESSION
        context.load_cert_chain(self.certfile, self.keyfile)
        if self.require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(self.client_ca)
        return context


@dataclass
class Stats:
    """Aggregate counters only. No query text, no client identifiers."""
    started_at: float = field(default_factory=time.time)
    queries: int = 0
    answered: int = 0
    servfail: int = 0
    rejected: int = 0
    connections: int = 0
    tls_failures: int = 0
    bytes_in: int = 0
    by_type: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"uptimeSeconds": round(time.time() - self.started_at, 1),
                "queries": self.queries, "answered": self.answered,
                "servfail": self.servfail, "refusedRequests": self.rejected,
                "connections": self.connections, "tlsFailures": self.tls_failures,
                "bytesIn": self.bytes_in, "queryTypes": dict(self.by_type)}


# ---------------------------------------------------------------------------
# HTTP/2 request handling
# ---------------------------------------------------------------------------

def decode_get_query(value: str) -> bytes:
    """RFC 8484 4.1: base64url, padding optional."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+=*", value or ""):
        raise ValueError("dns parameter is not base64url")
    padding = "=" * (-len(value.rstrip("=")) % 4)
    return base64.urlsafe_b64decode(value.rstrip("=") + padding)


def http_error(status: int, message: str) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    body = json.dumps({"error": status, "message": message}).encode()
    headers = [(b"content-type", b"application/json"),
               (b"content-length", str(len(body)).encode()),
               (b"cache-control", b"no-store")]
    return headers, body


class DohHandler:
    """One HTTP/2 connection. Holds no per-query state once a stream closes."""

    def __init__(self, resolver, config: ServerConfig, stats: Stats):
        self.resolver = resolver
        self.config = config
        self.stats = stats
        self.conn = H2Connection(config=H2Configuration(client_side=False,
                                                       header_encoding="utf-8"))
        self.conn.local_settings.max_concurrent_streams = config.max_streams
        self.conn.local_settings.max_frame_size = 16384
        self.pending: dict[int, dict] = {}

    # -- lifecycle ---------------------------------------------------
    def initiate(self) -> bytes:
        self.conn.initiate_connection()
        return self.conn.data_to_send()

    def handle(self, data: bytes) -> bytes:
        try:
            events = self.conn.receive_data(data)
        except ProtocolError:
            self.stats.rejected += 1
            return self.conn.data_to_send()
        for event in events:
            self._event(event)
        return self.conn.data_to_send()

    def _event(self, event) -> None:
        if isinstance(event, RequestReceived):
            self.pending[event.stream_id] = {
                "headers": {key.lower(): value for key, value in event.headers},
                "body": b"",
            }
        elif isinstance(event, DataReceived):
            state = self.pending.setdefault(event.stream_id, {"headers": {}, "body": b""})
            state["body"] += event.data
            self.conn.acknowledge_received_data(event.flow_controlled_length,
                                                event.stream_id)
            if len(state["body"]) > MAX_BODY:
                self._respond_error(event.stream_id, 413, "query too large")
        elif isinstance(event, StreamEnded):
            state = self.pending.pop(event.stream_id, None)
            if state is not None:
                self._dispatch(event.stream_id, state)
        elif isinstance(event, StreamReset):
            self.pending.pop(event.stream_id, None)
        elif isinstance(event, ConnectionTerminated):
            self.pending.clear()

    # -- dispatch ----------------------------------------------------
    def _dispatch(self, stream_id: int, state: dict) -> None:
        headers = state["headers"]
        method = headers.get(":method", "")
        path = headers.get(":path", "")
        self.stats.bytes_in += len(state["body"])
        path_only, _, query = path.partition("?")

        if path_only != DOH_PATH:
            self._respond_error(stream_id, 404, "unknown path")
            return

        accept = headers.get("accept", "")
        if accept and accept != "*/*" and DNS_MESSAGE not in accept:
            self._respond_error(stream_id, 406, "accept must be " + DNS_MESSAGE)
            return

        if method == "GET":
            match = re.search(r"(?:^|&)dns=([^&]*)", query)
            if not match:
                self._respond_error(stream_id, 400, "missing dns parameter")
                return
            try:
                payload = decode_get_query(match.group(1))
            except ValueError as exc:
                self._respond_error(stream_id, 400, str(exc))
                return
        elif method == "POST":
            content_type = headers.get("content-type", "")
            if DNS_MESSAGE not in content_type:
                self._respond_error(stream_id, 415,
                                    "content-type must be " + DNS_MESSAGE)
                return
            payload = state["body"]
        else:
            self._respond_error(stream_id, 405, "GET or POST only")
            return

        if not payload:
            self._respond_error(stream_id, 400, "empty DNS message")
            return
        self.stats.queries += 1
        self._answer(stream_id, payload)

    def _answer(self, stream_id: int, payload: bytes) -> None:
        try:
            query = R.parse_message(payload)
            if len(query.questions) != 1:
                self._respond_error(stream_id, 400, "exactly one question required")
                return
            qtype = str(query.questions[0].qtype)
            self.stats.by_type[qtype] = self.stats.by_type.get(qtype, 0) + 1
            response = R.answer_query(self.resolver, payload)
            rcode = R.parse_message(response).rcode
        except Exception:
            # The error path never echoes the question: an error message must not
            # leak the name that was asked for.
            self.stats.servfail += 1
            self._respond_status(stream_id, 200, b"", DNS_MESSAGE,
                                 extra=[(b"x-cleangeo-error", b"resolver-failure")])
            return
        if rcode == 2:
            self.stats.servfail += 1
        else:
            self.stats.answered += 1
        self._respond_status(stream_id, 200, response, DNS_MESSAGE,
                             extra=[(b"cache-control", b"no-store"),
                                    (b"pragma", b"no-cache")])

    def _respond_error(self, stream_id: int, status: int, message: str) -> None:
        self.stats.rejected += 1
        headers, body = http_error(status, message)
        self._respond_status(stream_id, status, body, "application/json", extra=headers)

    def _respond_status(self, stream_id: int, status: int, body: bytes,
                        content_type: str, extra=()) -> None:
        try:
            self.conn.send_headers(
                stream_id,
                [(b":status", str(status).encode()),
                 (b"content-type", content_type.encode()),
                 (b"content-length", str(len(body)).encode())] + list(extra or ()),
            end_stream=not body)
            if body:
                self.conn.send_data(stream_id, body, end_stream=True)
        except (H2Error, KeyError):
            self.stats.rejected += 1


class DohServer:
    """Threaded TLS listener. One thread per connection; queries stay in memory."""

    def __init__(self, resolver, config: ServerConfig, *, stats: Stats | None = None):
        config.validate()
        self.resolver = resolver
        self.config = config
        self.stats = stats or Stats()
        self._context = config.tls_context()
        self._server: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

    # -- lifecycle ---------------------------------------------------
    def bind(self) -> int:
        family = socket.AF_INET6 if ":" in self.config.host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.host, self.config.port))
        sock.listen(64)
        self._server = sock
        return sock.getsockname()[1]

    def serve_forever(self) -> None:
        if self._server is None:
            self.bind()
        assert self._server is not None
        while not self._stop.is_set():
            try:
                client, _address = self._server.accept()
            except OSError:
                break
            thread = threading.Thread(target=self._serve_one, args=(client,),
                                      daemon=True)
            thread.start()
            self._threads.append(thread)

    def shutdown(self) -> None:
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass

    # -- one connection ----------------------------------------------
    def _serve_one(self, raw: socket.socket) -> None:
        self.stats.connections += 1
        stream = raw
        try:
            if self._context is not None:
                try:
                    stream = self._context.wrap_socket(raw, server_side=True)
                except (ssl.SSLError, OSError):
                    # A TLS failure is counted, not logged with details that
                    # could identify the peer.
                    self.stats.tls_failures += 1
                    raw.close()
                    return
            self._http2_loop(stream)
        finally:
            try:
                stream.close()
            except OSError:
                pass
            if stream is not raw:
                try:
                    raw.close()
                except OSError:
                    pass

    def _http2_loop(self, stream) -> None:
        handler = DohHandler(self.resolver, self.config, self.stats)
        stream.settimeout(self.config.idle_timeout)
        stream.sendall(handler.initiate())
        while not self._stop.is_set():
            try:
                data = stream.recv(65535)
            except (socket.timeout, OSError):
                break
            if not data:
                break
            out = handler.handle(data)
            if out:
                stream.sendall(out)

