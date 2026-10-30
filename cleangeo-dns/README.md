# CleanGEO private DNS

A private DNS over HTTPS service you own end to end: your certificate, your
server, your recursive resolver, no third-party upstream.

```
browser --TLS 1.3--> your DoH server --DNSSEC-validated recursion--> authoritative servers
```

## What is here

| File | What it is |
|---|---|
| `resolver.py` | Iterative resolver. Walks the delegation chain from the root; validates DNSSEC from a pinned root anchor; never forwards to a public resolver. |
| `doh_server.py` | DoH endpoint: TLS 1.3 minimum, HTTP/2, RFC 8484 GET and POST. Refuses to start without a private TLS key. |
| `doh_client.py` | Small DoH client. Fails closed — it never retries over plain DNS. |
| `dns_probe.py` | Proves the encrypted path works: TLS version, ALPN, certificate, real query, optional cross-check against a control resolver. |
| `browser_integration.py` | The Chromium/Electron switches and policy for the endpoint, plus static verification. |
| `keys.py` | Certificate/key checks (refuses world-readable keys), expiry reporting, ACME layout, CSTP pin files. |
| `server.py` | Entry point: `serve`, `check`. |
| `cstp.py` | **Experimental**, isolated protocol. See `CSTP-SPEC.md`. Not on any production path. |
| `THREAT-MODEL.md` | What is protected, what is exposed, what is not claimed. |
| `DEPLOY.md` | Real deployment steps, systemd unit, verification. |
| `CSTP-SPEC.md` | Byte-level protocol specification and the review it still needs. |

Tests: `test_resolver.py` (20), `test_doh.py` (16), `test_cstp.py` (26),
`test_integration.py` (27).

## Quick start

```
pip install cryptography h2
python server.py check --domain dns.example.com \
    --cert-dir /etc/letsencrypt/live/dns.example.com
python server.py serve --domain dns.example.com \
    --cert-dir /etc/letsencrypt/live/dns.example.com
```

Then, from another machine:

```
python dns_probe.py dns.example.com --control dns.adguard-dns.com
```

## Tests

```
python test_resolver.py     # DNSSEC, wire format, delegation walking
python test_doh.py          # HTTP/2 shapes, TLS policy, stats hygiene
python test_cstp.py         # handshake, framing, replay, rotation
python test_integration.py  # config gates, key hygiene, browser config
```

The DNSSEC tests are not mocks: `tests/_load.py` generates real ECDSA P-256 keys
and real RRSIG signatures, so a passing test means `cryptography` actually
verified a signature. A forged signature must produce SERVFAIL, and a test
asserts exactly that.

## The three claims this project makes, and how each is checked

1. **Queries to the server are encrypted.** `dns_probe.py` inspects the
   negotiated TLS version and ALPN on a live connection, then makes a real
   query. A configuration file is not accepted as evidence.
2. **Resolution is independent.** `resolver.py` has no upstream setting, and
   `test_only_talks_to_authoritative_servers` asserts every host contacted is
   one discovered in the delegation chain.
3. **DNSSEC failures are not answered.** Bogus → SERVFAIL, with tests for
   forged signatures, expired signatures, and a wrong trust anchor.

## What this is not

- Not anonymous: the server sees your IP.
- Not leak-proof: `THREAT-MODEL.md` §6 lists the leaks that remain, including
  the endpoint hostname being visible to your ISP so DoH can bootstrap.
- Not a replacement for TLS 1.3: that is still what protects real traffic.
- Not audited, and not post-quantum. The library has ML-KEM, this build's
  backend does not support it, so no such claim is made.
- `cstp.py` is unreviewed. It is inert until someone independent reviews it.

## No Electron app in this repository

Verified rather than assumed: this project contains no Electron or Chromium
source. `browser_integration.py` therefore emits the exact switches and policy
a Chromium-based browser needs, and verifies them statically and live. If the
browser source is added later, the values in `ChromiumConfig` are what its main
process should apply before `app.whenReady()`.
