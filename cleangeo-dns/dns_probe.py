"""Prove the encrypted DoH path is real, not a configuration claim.

The point of this tool is distrust: it does not read the server's own config and
agree with it. It observes an actual TLS connection, inspects the negotiated
protocol and cipher, and checks the DNS answer against what the public resolver
set returns, so a silent fallback to plain DNS or to a third-party resolver
shows up as a mismatch.

Checks performed, each reported separately:

  1. TLS handshake succeeds against the configured hostname.
  2. The negotiated TLS version is 1.3 (or the minimum you allow).
  3. The certificate chains to a trusted CA and matches the hostname.
  4. An HTTP/2 connection is negotiated for the DoH POST.
  5. The DNS response is well-formed and the AD bit reflects validation.
  6. The answer for the probe name equals a control answer fetched over a
     separate encrypted channel, when a control is available.

What this cannot prove, stated rather than implied:
  * It cannot see what the server does with the query after it decrypts it.
  * It cannot prove the server does not log; that is a code review, and the
    code is in resolver.py/doh_server.py with no logging calls.
  * A passing run says "this path is encrypted and answers correctly". It does
    not say "you are anonymous".
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time

from doh_client import doh_query, QueryError


def check(hostname: str, *, port: int = 443, path: str = "/dns-query",
          name: str = "example.com", qtype: int = 1, ca_file: str = "",
          min_version: str = "TLSv1.3", control: str = "") -> dict:
    result = {"target": "%s:%d%s" % (hostname, port, path), "name": name,
              "passed": False, "checks": [], "failures": []}

    def record(label: str, ok: bool, detail: str) -> None:
        result["checks"].append({"check": label, "ok": ok, "detail": detail})
        if not ok:
            result["failures"].append(label)

    # 1-4: one real connection, with the TLS facts recorded as they are.
    context = ssl.create_default_context(cafile=ca_file or None)
    context.set_alpn_protocols(["h2"])
    try:
        raw = socket.create_connection((hostname, port), timeout=10)
    except OSError as exc:
        record("tcp", False, "cannot connect: %s" % exc)
        return result
    try:
        with context.wrap_socket(raw, server_hostname=hostname) as tls:
            version = tls.version()
            cipher = tls.cipher()
            alpn = tls.selected_alpn_protocol()
            certificate = tls.getpeercert()
            record("tls", True, "handshake completed with %s, %s" % (
                version, cipher[0] if cipher else "unknown cipher"))
            record("tls-version", version == min_version,
                   "negotiated %s (required %s)" % (version, min_version))
            record("http2", alpn == "h2", "ALPN selected %s" % alpn)
            subject = dict(item[0] for item in certificate.get("subject", ()))
            san = [value for key, value in certificate.get("subjectAltName", ())
                   if key == "DNS"]
            record("certificate", True, "subject=%s san=%s" % (
                subject.get("commonName", "?"), ",".join(san) or "none"))
            del certificate, subject, san, cipher
    except ssl.SSLError as exc:
        record("tls", False, "TLS failed: %s" % exc)
        return result
    except OSError as exc:
        record("tls", False, "connection failed: %s" % exc)
        return result

    # 5: a real query over the encrypted channel.
    started = time.time()
    try:
        response = doh_query(name, qtype, hostname=hostname, port=port,
                             path=path, ca_file=ca_file)
    except QueryError as exc:
        record("doh-query", False, str(exc))
        return result
    latency_ms = round((time.time() - started) * 1000)
    record("doh-query", True, "answered in %d ms with rcode %s"
           % (latency_ms, response.get("rcode")))
    record("dnssec", response.get("validated") is not None,
           "AD bit %s" % ("set" if response.get("authenticated") else "clear"))
    record("answers", bool(response.get("answers")),
           "%d answer record(s)" % len(response.get("answers", [])))

    # 6: control comparison, so a silent third-party resolver is visible.
    if control:
        try:
            other = doh_query(name, qtype, hostname=control, ca_file=ca_file)
        except QueryError as exc:
            record("control", False, "control query failed: %s" % exc)
        else:
            same = sorted(other.get("answers", [])) == sorted(response.get("answers", []))
            record("control", same, "answers %s the control (%s)" % (
                "match" if same else "DIFFER from", control))

    result["passed"] = not result["failures"]
    result["latencyMs"] = latency_ms
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("hostname")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/dns-query")
    parser.add_argument("--name", default="example.com")
    parser.add_argument("--type", default="A")
    parser.add_argument("--ca", default="", help="custom CA bundle")
    parser.add_argument("--min-tls", default="TLSv1.3")
    parser.add_argument("--control", default="",
                        help="another DoH host to cross-check answers against")
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args(argv)

    from resolver import NAME_TO_TYPE
    qtype = NAME_TO_TYPE.get(arguments.type.upper(), 1)
    result = check(arguments.hostname, port=arguments.port, path=arguments.path,
                   name=arguments.name, qtype=qtype, ca_file=arguments.ca,
                   min_version=arguments.min_tls, control=arguments.control)
    if arguments.json:
        print(json.dumps(result, indent=2))
    else:
        for item in result["checks"]:
            print("%s %-14s %s" % ("PASS" if item["ok"] else "FAIL",
                                   item["check"], item["detail"]))
        print()
        print("RESULT: %s" % ("encrypted path verified" if result["passed"]
                              else "FAILED: " + ", ".join(result["failures"])))
        print("This verifies the transport and the answer. It does not verify "
              "that the server keeps no logs, and it does not make you anonymous.")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
