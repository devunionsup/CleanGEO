# Traffic analysis: what an observer can still learn

Requirement five asked for an investigation into resistance to traffic analysis.
This is the result of that investigation, including the parts that came out
badly. Nothing here is a claim of anonymity, and no countermeasure below is
enabled by default in the production path.

## 1. Who the observers are

| Observer | Position | Sees |
|---|---|---|
| Local network / ISP | between client and `dns.cleangeo.net` | TLS to one IP, packet sizes, timing, volume |
| The server operator (you) | the endpoint itself | client IPs, query timing, query names unless suppressed |
| An on-path attacker who breaks TLS | cannot, without a CA compromise | nothing useful |
| Certificate authority | issues the cert | that the name exists; not the traffic |

The first two are the ones that matter. DNSSEC and TLS 1.3 do not hide *that*
someone used your resolver, or *when*, or *how much*.

## 2. What is already hidden

- **Query contents.** TLS 1.3 with a real certificate. A passive observer on the
  path sees a TLS record stream, not a DNS name.
- **The endpoint hostname, mostly.** It appears in the TLS ClientHello SNI, which
  TLS 1.3 encrypts only with Encrypted Client Hello (ECH), and ECH needs the
  client and the CDN to both support it. So in practice: the SNI for
  `dns.cleangeo.net` is visible to the local network.
- **Where resolution goes next.** The server recurses from the root itself, so a
  third party does not see your queries in a forwarded stream. The authoritative
  servers still see the *server's* IP asking, not yours.

## 3. What is not hidden, and cannot be by this design

### 3.1 Name inference from sizes

A DoH query is a POST or GET whose body length tracks the encoded name length.
An observer who knows the candidate set can sometimes map a length to a name:
`a.example.com` and `b.example.com` produce the same length, but
`news.example.com` and `mail.example.com` do not. With HTTPS the TLS record
padding is coarse, so the mapping survives.

### 3.2 Response timing

The resolver's own timing leaks structure: an answer already in cache returns in
about a millisecond; a cold query that must walk root → TLD → authoritative
takes tens to hundreds. An observer measuring round-trip times can tell
"popular name, cached" from "novel name", which over many queries is a
popularity fingerprint for a household.

### 3.3 Connection reuse and burst shape

A page load produces a burst of many small queries. The burst shape — how many
questions, in what rhythm, over how long — correlates with the site being
visited. This is the classic website-fingerprinting problem, and it is not
solved here, nor is it solved by DoH in any deployed form.

### 3.4 Server-side visibility

The DoH server necessarily sees the client IP, the timing and the query. If it
logged queries, it would be the most informative observer of all. That is why
the server's stats are aggregate-only counters with no names and no addresses,
and why there is no query log at all. This is a *behaviour* property, and
`test_stats_are_aggregate_only` and `test_server_never_logs_query_names` assert
it — but an operator who adds logging would undo it, so it is a policy as much
as a code property.

## 4. Countermeasures examined

Each was tried or specified, then evaluated honestly.

### 4.1 Query padding

EDNS(0) Padding (RFC 7830) pads the DNS message to a multiple of a block size.
Effect: query lengths become one of a few values. Cost: up to a block of extra
bytes per query, and the padding level is negotiated separately from DoH, so
clients that ignore it gain nothing.

**Verdict:** worth deploying at 128-byte blocks. Reduces size inference to a
coarse bucket. Does not defeat it: 128 bytes is only a handful of name lengths.

### 4.2 Batching (many questions, one request)

One DoH POST can carry one DNS message; batching would mean many questions in
one message, which DNS discourages and many resolvers refuse. Encapsulating
several HTTP requests into one connection is what HTTP/2 already does, and it
hides little because the record sizes remain.

**Verdict:** rejected. It breaks RFC 8484 expectations for less privacy than it
appears to buy.

### 4.3 Response timing normalisation

Hold every answer for a fixed floor (say 150 ms) so cache hits and cold lookups
look alike. Effect: removes the cached/uncached distinction. Cost: adds latency
to every query, in a path where latency is the entire point of a DNS resolver,
and it is only detectable by an observer who already sees per-query timing.

**Verdict:** rejected for the production path. It trades a real, felt cost
against a partial, unproven gain. Recorded here so that the trade was made
deliberately rather than overlooked.

### 4.4 Cover traffic

Send dummy queries at a steady rate so real ones do not stand out. Effect: in
theory a flat rate hides bursts. Cost: proportional bandwidth and battery for
the client, plus load on the server; and a steady rate that is high enough to
hide a page load is a considerable constant drain on a phone.

**Verdict:** not implemented. It is the honest answer that a privacy feature
that costs every user constant battery is a feature most users turn off.

### 4.5 Multiplexing all clients through a shared egress

If many clients share the server, the server's own outbound queries mix them, so
an authoritative server sees a blended pattern. Effect: real, and it comes for
free with a shared resolver. Cost: the *operator* now sees all of it, which is
worse for anyone who distrusts the operator. This is the central tension of
private DNS and it is why "run your own" was the choice made here.

## 5. The experimental protocol's contribution

`cstp.py` (see `CSTP-SPEC.md`) fixes frame size at up to 16 KiB and uses a
sliding replay window with explicit counters. That removes *one* class of leak —
per-message length variation within a stream — for traffic that uses it. It does
not address timing or burst shape, and it is not on any production path, so it
currently protects nothing in practice. It is included because the specification
is the deliverable; claiming it improves privacy today would be false.

## 6. What could be built next, honestly ranked

1. **EDNS padding at 128 bytes, negotiated, with the padding level logged in
   stats.** Cheap, standard, modest gain. This is the one worth doing first.
2. **A local cache in front of the resolver**, so repeated names never leave the
   device. Removes the query entirely rather than hiding it, which beats every
   countermeasure above.
3. **ECH**, once the certificate is behind a CDN that supports it. Hides the
   endpoint name from the local network.
4. **Oblivious HTTP (RFC 9458)** with a relay you do not operate. This is the
   only design here that hides the client IP from the resolver, and it needs a
   second party, which is exactly what "run your own" was avoiding.

Anything beyond that — cover traffic, fixed-rate scheduling, mixing networks —
is a research system, not something to ship on a phone, and none of it makes a
user anonymous.

## 7. Summary

| Property | Status |
|---|---|
| Query contents hidden from the network | yes, TLS 1.3 |
| Endpoint name hidden from the network | no (SNI visible) |
| Query length hidden | no, only coarsened by optional padding |
| Cached vs cold distinguishable by timing | yes |
| Site fingerprintable from burst shape | yes |
| Client IP hidden from the resolver | no |
| Anonymous | **no, and not claimed** |
