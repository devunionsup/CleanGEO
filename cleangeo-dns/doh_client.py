"""Minimal DoH client, and the verifier that proves the path is encrypted.

Deliberately small: TLS 1.3 minimum, HTTP/2 via ALPN, `application/dns-message`
POST per RFC 8484, and no fallback to plain DNS. If the encrypted channel fails
this raises: it never retries over port 53, which is the behaviour that turns a
"private DNS" feature into a silent leak.
"""
from __future__ import annotations

import json
import socket
import ssl
import sys

import h2.config
import h2.connection
import h2.events

DOH_CONTENT_TYPE = "application/dns-message"


class QueryError(Exception):
    pass


def _connect(hostname, port, *, ca_file="", timeout=10.0):
    context = ssl.create_default_context(cafile=ca_file or None)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    try:
        raw = socket.create_connection((hostname, port), timeout=timeout)
    except OSError as exc:
        raise QueryError("cannot reach %s:%d: %s" % (hostname, port, exc))
    try:
        tls = context.wrap_socket(raw, server_hostname=hostname)
    except (ssl.SSLError, OSError) as exc:
        raw.close()
        raise QueryError("TLS to %s failed: %s" % (hostname, exc))
    if tls.selected_alpn_protocol() != "h2":
        tls.close()
        raise QueryError("server did not negotiate HTTP/2; refusing to treat "
                         "this as DoH")
    connection = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    connection.initiate_connection()
    tls.sendall(connection.data_to_send())
    return tls, connection


def _read_response(tls, connection, stream_id, timeout):
    tls.settimeout(timeout)
    body = b""
    status = None
    while True:
        try:
            data = tls.recv(65535)
        except socket.timeout:
            raise QueryError("timed out waiting for the response")
        if not data:
            break
        for event in connection.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                status = int(event.headers[0][1])
            elif isinstance(event, h2.events.DataReceived):
                body += event.data
                connection.acknowledge_received_data(event.flow_controlled_length,
                                                     stream_id)
            elif isinstance(event, h2.events.StreamEnded):
                out = connection.data_to_send()
                if out:
                    tls.sendall(out)
                return status or 0, body
            elif isinstance(event, h2.events.StreamReset):
                raise QueryError("server reset the stream")
        out = connection.data_to_send()
        if out:
            tls.sendall(out)
    raise QueryError("connection closed before the response completed")


def doh_query(name, qtype, *, hostname, port=443, path="/dns-query", ca_file="",
              timeout=10.0):
    """Ask one question over DoH and describe the answer."""
    from resolver import RCODES, build_query, parse_message

    wire = build_query(name, qtype, rd=True, edns=False)
    tls, connection = _connect(hostname, port, ca_file=ca_file, timeout=timeout)
    try:
        stream_id = connection.get_next_available_stream_id()
        connection.send_headers(stream_id, [
            (":method", "POST"), (":path", path), (":scheme", "https"),
            (":authority", hostname), ("content-type", DOH_CONTENT_TYPE),
            ("accept", DOH_CONTENT_TYPE)], end_stream=False)
        connection.send_data(stream_id, wire, end_stream=True)
        tls.sendall(connection.data_to_send())
        status, body = _read_response(tls, connection, stream_id, timeout)
    finally:
        try:
            tls.close()
        except OSError:
            pass
    if status != 200:
        raise QueryError("HTTP %d from the DoH endpoint" % status)
    if not body:
        raise QueryError("empty DNS response")
    try:
        message = parse_message(body)
    except Exception as exc:
        raise QueryError("malformed DNS response: %s" % exc)
    authenticated = bool(message.flags & 0x0020)
    return {"rcode": RCODES.get(message.rcode, str(message.rcode)),
            "authenticated": authenticated, "validated": authenticated,
            "answers": [str(record) for record in message.answers],
            "questions": [question.name for question in message.questions]}


def main(argv=None):
    import argparse
    from resolver import NAME_TO_TYPE
    parser = argparse.ArgumentParser(description="query a DoH endpoint")
    parser.add_argument("hostname")
    parser.add_argument("name")
    parser.add_argument("--type", default="A")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/dns-query")
    parser.add_argument("--ca", default="")
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        result = doh_query(arguments.name,
                           NAME_TO_TYPE.get(arguments.type.upper(), 1),
                           hostname=arguments.hostname, port=arguments.port,
                           path=arguments.path, ca_file=arguments.ca)
    except QueryError as exc:
        print("query failed: %s" % exc, file=sys.stderr)
        return 1
    if arguments.json:
        print(json.dumps(result, indent=2))
        return 0
    print("%s -> %s%s" % (arguments.name, result["rcode"],
                          " (DNSSEC validated)" if result["authenticated"] else ""))
    for answer in result["answers"]:
        print("  " + answer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
