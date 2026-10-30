# CleanGEO private DNS — threat model and privacy analysis

This document states what the system protects, what it exposes, and which
claims are simply not true. It is written to be useful to someone deciding
whether to trust it, not to make the project look good.

## 1. What the system is

Three separately verified parts:

| Part | File | Role |
|---|---|---|
| Recursive resolver | `resolver.py` | Walks the delegation chain from the root, validates DNSSEC, never forwards to a public resolver |
| DoH/DoT server | `doh_server.py` | TLS 1.3 + HTTP/2 endpoint at `/dns-query`, RFC 8484 |
| Browser integration | `browser_integration.py` | Chromium switches/policy for the endpoint, plus verification |

Plus one part that is **not** production: `cstp.py`, the experimental
end-to-end layer described in `CSTP-SPEC.md`.

## 2. Trust boundaries

```
 browser  --TLS1.3-->  our server  --plaintext DNS/53-->  authoritative servers
   |                        |
   |                        +-- sees: client IP, query, time
   +-- trusts: our TLS cert and the host running it
```

The important asymmetry: **the client leg is encrypted, the server-to-authority
leg is not.** That is how DNS works, not a shortcut taken here. Any provider
claiming "fully encrypted DNS" while recursing itself is describing this same
picture.

## 3. Data the server necessarily sees

- The client's IP address (it is a TCP/TLS connection).
- The question in each query, after TLS termination, in memory.
- Timing and size of each query.
- Aggregate counters (`Stats`): counts by type, bytes, connections.

## 4. Data the server does not collect

Verified by reading the code, not merely asserted:

- No request logging: `doh_server.py` contains no `logging` calls and no writes
  to disk. Errors return a DNS SERVFAIL and increment a counter.
- No query text in statistics: `Stats.to_dict()` emits counters only; there is
  a test asserting the serialised stats contain no hostname or address.
- No cookies, no client identifiers, no session store. Each HTTP/2 stream is
  dropped after its response.
- No browsing history: the server has no concept of a user and no persistent
  state between connections other than the answer cache (keyed by name/type,
  held in memory, TTL-capped, and not written down).

**What this does not prove:** a host operator can still run `tcpdump`, and a
kernel-level observer sees packets. "We keep no logs" is a statement about this
code, not about the machine it runs on. If that matters to you, run your own
server — the point of this project is that you can.

## 5. Independent resolution: what "no forwarding" means

`Resolver` starts at the 13 root servers and follows referrals. It has no
`upstream` setting, and the string `1.1.1.1`/`8.8.8.8`/AdGuard does not appear
in `resolver.py`. There is a test (`test_only_talks_to_authoritative_servers`)
asserting every host contacted during a resolution is one of the authoritative
servers discovered in the delegation chain.

Unavoidable communications, stated plainly:

1. **Root servers** see a query for the TLD of every name you look up.
2. **TLD servers** see the second-level label.
3. **Authoritative servers** see the full name, and the IP of this server.
4. **The certificate authority** (Let's Encrypt or similar) sees the endpoint
   hostname, and publishes it in Certificate Transparency logs. The existence of
   the DNS service is therefore public.
5. **The hosting provider** sees connections to those servers and the traffic
   volume.

None of these receive the query from the client directly; all of them see the
server, not you. That is the actual privacy gain: your ISP sees one TLS
connection to one host.

## 6. DNS leakage vectors and how each is handled

| Leak | Handling | Status |
|---|---|---|
| Browser falls back to plaintext DNS | `--dns-over-https-mode=secure`, and the client refuses a non-h2 connection | Implemented; `verify_config` fails if the mode is not `secure` |
| OS resolver uses DHCP DNS in parallel | The Apple profile (`cleangeo-network.mobileconfig`) sets `com.apple.dnsSettings.managed` system-wide | Previous step, still valid |
| DNS prefetching / speculative resolution | `DnsPrefetchingEnabled: false`, `NetworkPredictionOptions: 2` in the policy | Emitted, not enforced by the server |
| The DoH endpoint's own name leaks | `--host-resolver-rules` excludes the endpoint host from the tunnel so it bootstraps over system DNS | Necessary trade-off, documented: the endpoint hostname is visible to your ISP |
| IPv6 bypass (AAAA to a v4-only proxy) | Server listens on the configured family; the client uses whatever the OS gives it | **Not fully solved.** See limitations |
| Guest/other apps using system DNS | Only the OS profile covers this | Depends on the profile being installed |
| Plain DNS/53 still reachable | Not blocked by this system | Not handled; a firewall rule is required |

## 6.1 "Verify that DNS actually uses the encrypted endpoint"

A configuration file is not evidence. Two independent checks exist:

- `dns_probe.py` opens a real TLS connection, asserts TLS 1.3 and ALPN `h2`,
  performs a POST query, inspects the AD bit, and optionally cross-checks the
  answer against another DoH host. A silent fallback shows up as a failed
  handshake or a mismatched answer.
- `browser_integration.py --verify-live` runs the same query through the same
  client code the probe uses.

Neither can see inside the server after decryption; that is why §4 is argued
from the source rather than from a test.

## 7. DNSSEC: what is real and what is not

- The chain is validated from a pinned root anchor: root DNSKEY against
  built-in anchors (KSK-2017 20326 and KSK-2024 38696), each child DNSKEY
  against its parent's DS, denial of existence via NSEC/NSEC3.
- Three outcomes are kept distinct, because merging them is how "supports
  DNSSEC" turns into a lie:
  - `validated` — a full chain verified; the AD bit is set;
  - `insecure` — a signed parent proves by signed denial that the child zone is
    unsigned. The data is **not** DNSSEC-protected; that is a property of the
    zone.
  - **bogus** → SERVFAIL. Never a best-effort answer. Forged signatures,
  expired signatures, and a wrong trust anchor all produce SERVFAIL, and there
  are tests for each.
- **Not implemented:** NSEC3 opt-out edge cases beyond basic coverage checks,
  algorithm rollover edge cases, and aggressive NSEC caching. Unsupported
  algorithms are treated as unvalidated, not as valid.

## 7.1 DNSSEC does not give you privacy

DNSSEC authenticates; it does not encrypt. An on-path observer still reads the
question. The encryption comes from the TLS hop, and from CSTP if it is ever
approved.

## 8. Key management

- TLS private keys must not be group/world readable; `doh_server.ServerConfig`
  **refuses to start** if they are (mode `0600` required), and there is a test.
- Keys are never in the repository, never in logs, never in the DoH responses.
  `keys.py` writes to a path you choose; nothing writes into the project.
- Certificate expiry is inspected (`keys.check_pair`) and reported; the server
  warms when fewer than 21 days remain.
- ACME layout supported (`fullchain.pem` + `privkey.pem`) because that is how
  renewal actually works in production.
- The CSTP pin is a separate 32-byte Ed25519 public key in its own file. It is
  public, so it is mode `0644`; it is not a substitute for the TLS certificate.

## 9. Traffic analysis

Nothing here hides the *shape* of traffic: sizes, counts, timing, and session
duration are all visible to anyone on the path and to the server. No padding,
batching, or timing normalisation is implemented. `CSTP-SPEC.md` §9 discusses
what could be done and what it would cost. This system does not claim encrypted
traffic hides metadata; it does not.

## 10. Known limitations

1. **The recursive leg is unencrypted.** Server-to-authority DNS is plaintext
  by protocol definition. Anyone between your server and the authoritative
  servers sees the queries.
2. **Your hosting provider can read queries** unless CSTP is deployed and
  reviewed. TLS terminates at the host.
- **No IPv6/IPv4 split-brain protection** beyond what the OS profile does.
- **No DoS protection or rate limiting.** The server is threaded and will
  accept as many connections as it can; there is no quota.
- **The answer cache is memory-only and per-process**, so it is lost on restart
  and not shared across workers.
- **No client authentication.** Anyone who can reach the endpoint can query it.
  If that matters, put it behind a private network or add mTLS
  (`require_client_cert` exists and is tested at the configuration level).
- **HTTP/3 (DoQ/DoH3) is not implemented.** DoH over HTTP/2 and DoT only.
- **No backward compatibility with older TLS.** TLS 1.3 is pinned as the
  minimum; some old clients will fail rather than downgrade. That is intended.
- **Not audited.** No independent security review of this code has taken place.
  It should not be described as audited or as anonymous.

## 10.1 Explicitly not claimed

- Not "anonymous". The server sees your IP.
- Not "leak-proof". §6 lists the leaks that remain.
- Not "unloggable". The code logs nothing; the host can.
- Not "more secure than TLS 1.3", which is still what protects real traffic.
- Not "post-quantum". ML-KEM is available in the library used here but is
  **not supported by this build's backend**, so no post-quantum claim is made.

## 11. If you are evaluating this

Ask these, in this order:

1. Do the tests actually exercise cryptography, or fake the verdict? (Here:
   real ECDSA P-256 signatures in `tests/dnsfixtures.py`, real AEAD frames in
   `test_cstp.py`.)
2. Does a failed validation produce an answer anyway? (Here: no — SERVFAIL.)
3. Is the key readable by other users? (Here: the server refuses to start.)
4. Does a failure fall back to plaintext? (Here: neither the resolver nor the
   DoH client falls back.)
4. Does the code claim privacy it cannot deliver? (Here: §9 and §10 say
   otherwise, in the code as well as the docs.)
