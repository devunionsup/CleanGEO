#!/usr/bin/env python3
"""CleanGEO private DNS server entry point.

    python server.py serve  --domain dns.example.com --cert /etc/.../fullchain.pem \\
                            --key /etc/.../privkey.pem
    python server.py check  --domain dns.example.com
    python server.py self-test-query www.example.com

`check` validates configuration and prints what it verified. It does not claim
the server is live; only `serve` shows a live connection, and only a real query
proves the path works. `dns_probe.py` is what proves encryption is actually in
use, by comparing the observed resolver identity against third-party resolvers.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import ssl
import sys
import threading
import time

from tests._load import R

import doh_server
import keys
from doh_server import ConfigError, DohServer


def build_config(args):
    certfile, keyfile = args.cert, args.key
    if args.cert_dir:
        certfile, keyfile = keys.chain_files(args.cert_dir)
    return doh_server.ServerConfig(
        host=args.host, port=args.port, certfile=certfile or "", keyfile=keyfile or "",
        require_client_cert=bool(args.client_ca),
        client_ca=args.client_ca or "",
        allow_insecure_http=bool(args.insecure_http),
        idle_timeout=float(args.idle_timeout))


def command_serve(arguments) -> int:
    config = build_config(arguments)
    try:
        config.validate()
    except ConfigError as exc:
        print("configuration error: %s" % exc, file=sys.stderr)
        return 2
    if config.certfile:
        info = keys.check_pair(config.certfile, config.keyfile)
        print("certificate: %s" % info.subject)
        print("  expires: %s (%d days)" % (info.not_after, info.days_left))
        if not info.fresh_enough:
            print("  WARNING: fewer than %d days left, renew now" % keys.WARN_DAYS,
                  file=sys.stderr)

    resolver = R.Resolver(require_dnssec=not arguments.no_dnssec)
    server = DohServer(resolver, config)
    port = server.bind()
    scheme = "http" if config.allow_insecure_http else "https"
    print("listening on %s://%s:%d/dns-query" % (scheme, arguments.host, port))
    if config.allow_insecure_http:
        print("WARNING: plain HTTP. Development only; queries are NOT encrypted.",
              file=sys.stderr)

    def handle_signal(_signum, _frame):
        server.shutdown()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    print(json.dumps(server.stats.to_dict()), file=sys.stderr)
    return 0


def command_check(arguments) -> int:
    problems = []
    config = build_config(arguments)
    try:
        config.validate()
    except ConfigError as exc:
        problems.append(str(exc))
    if config.certfile and not problems:
        try:
            info = keys.check_pair(config.certfile, config.keyfile)
            print("certificate OK: %s" % info.subject)
            print("  valid until %s (%d days left)" % (info.not_after, info.days_left))
            if "dns." in info.subject or info.sans:
                print("  SANs: %s" % (", ".join(info.sans) or "none"))
            if not info.fresh_enough:
                problems.append("certificate expires in %d days" % info.days_left)
        except keys.KeyError_ as exc:
            problems.append(str(exc))

    resolver = R.Resolver(require_dnssec=not arguments.no_dnssec)
    print("resolver: iterative from the root, DNSSEC %s"
          % ("required" if resolver.require_dnssec else "optional"))
    print("  trust anchors: %d" % len(resolver.anchors))
    print("  root hints: %d" % len(resolver.hints))
    if not resolver.require_dnssec:
        print("  NOTE: DNSSEC validation disabled; answers may not be authenticated")

    print("domain: %s" % (arguments.domain or "unset"))
    if not arguments.domain:
        problems.append("no --domain set; clients cannot build a DoH URL")
    if problems:
        for problem in problems:
            print("PROBLEM: %s" % problem, file=sys.stderr)
        return 1
    print("configuration OK. This does not prove the server is reachable; run "
          "serve and then dns_probe.py.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="CleanGEO private DNS server")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("serve", "check"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--host", default="0.0.0.0")
        sub.add_argument("--port", type=int, default=443)
        sub.add_argument("--domain", default=os.environ.get("CLEANGEO_DNS_DOMAIN", ""))
        sub.add_argument("--cert", default="")
        sub.add_argument("--key", default="")
        sub.add_argument("--cert-dir", default="")
        sub.add_argument("--client-ca", default="")
        sub.add_argument("--idle-timeout", type=float, default=30.0)
        sub.add_argument("--no-dnssec", action="store_true")
        sub.add_argument("--insecure-http", action="store_true")

    arguments = parser.parse_args(argv)
    if arguments.command == "serve":
        return command_serve(arguments)
    return command_check(arguments)


if __name__ == "__main__":
    sys.exit(main())
