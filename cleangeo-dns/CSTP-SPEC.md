# CleanGEO Secure Transport Protocol (CSTP) — experimental specification

**Status: EXPERIMENTAL / NOT FOR PRODUCTION TRAFFIC.**
`cstp.py` is isolated from the production DoH path (`doh_server.py`). Nothing in
`server.py` constructs a CSTP session. Enabling it for real users requires the
review described in §11 first.

This document specifies what the code actually does, byte for byte, and states
what is unproven about it. It does not claim the protocol is secure because it
is ours, because it passes its tests, or because the primitives are standard.

---

## 1. Purpose and scope

CSTP is a second, end-to-end encryption layer designed to sit *inside* TLS 1.3,
so that a party terminating TLS at the host — the VPS operator, a load
balancer, a CDN in front of the endpoint — cannot read DNS questions or link
them to a client.

Scope:
- one client, one server, one long-lived bidirectional session;
- frames of up to 16 KiB, carrying arbitrary bytes (a DoH-style exchange);
- server authentication by pinned Ed25519 key; client authentication by
  possession of the session keys derived from the key exchange.

Out of scope: client identity/anonymity (a pinned server key does not hide the
client), traffic analysis resistance (§9), and denial of service.

**CSTP is not a replacement for TLS.** It assumes TLS 1.3 already provides
confidentiality against the network. Its only job is to add a boundary the TLS
terminator cannot cross.

## 2. Threat model

| Adversary | Capability | CSTP effect |
|---|---|---|
| Passive network observer | sees TLS records only | No change: TLS already protects this. |
| TLS terminator at the host | reads plaintext inside TLS | Reads only CSTP frames; cannot derive keys without a party's X25519 secret. |
| Active MITM without the server key | can modify/drop/replay | Handshake fails on the pin, or frames fail AEAD; downgrade refused. |
| Replay attacker | records and resends frames | Rejected by the 64-frame sliding window and epoch binding. |
| Stolen long-term server key | signs as the server | Past sessions stay secret (ephemeral X25519). Future sessions are forgeable — pin rotation is required. |
| Compromised client | holds session + pin | Can impersonate that client; cannot read other clients. |

Not addressed: an adversary who controls both endpoints, endpoint compromise
before the session, and traffic-shape inference (§9).

## 3. Primitives

| Function | Choice | Reference |
|---|---|---|
| Key agreement | X25519, ephemeral per session | RFC 7748 |
| KDF | HKDF-SHA256 | RFC 5869 |
| AEAD | ChaCha20-Poly1305, 96-bit nonce | RFC 8439 |
| Server identity | Ed25519 | RFC 8032 |
| Key confirmation | HMAC-SHA256 | RFC 2104 |

No new cipher, no modified round function, no custom MAC, no bespoke padding
scheme. Everything original here is *construction*, which is exactly the part
that needs review.

## 4. Handshake

Four messages. All integers are big-endian. `||` is concatenation.

```
CLIENT_HELLO  = 0x10 || version:u8 || client_random:32 || client_eph:32 || time:u32
SERVER_HELLO  = 0x11 || version:u8 || server_random:32 || server_eph:32 ||
                server_identity:32 || time:u32 || signature:64
CLIENT_FINISH = 0x12 || hmac:32
SERVER_FINISH = 0x13 || hmac:32
```

1. **CLIENT_HELLO.** Client picks `version` (currently 1), a 32-byte random, an
   ephemeral X25519 key, and its clock.
2. **SERVER_HELLO.** Server picks the *highest* version it supports among those
   offered (it may not choose lower — see §7), generates its own random and
   ephemeral key, and signs
   `SERVER_HELLO_without_signature || client_random` with its Ed25519 identity
   key. Including `client_random` binds the signature to this handshake.
3. **Transcript.**
   ```
   t1 = SHA256( len(CLIENT_HELLO) || CLIENT_HELLO )
   t2 = SHA256( t1 || len(SERVER_HELLO) || SERVER_HELLO || len(client_random) || client_random )
   ```
   Length prefixes prevent concatenation ambiguity.
4. **Keys.**
   ```
   shared  = X25519(eph_priv, peer_eph_pub)
   master  = HKDF-SHA256(secret=shared, salt=t2, info="cleangeo-cstp-v1 master")
   c2s     = HKDF-SHA256(secret=master, salt=t2, info="cleangeo-cstp-v1 kdf"||epoch||" c2s")
   s2c     = HKDF-SHA256(secret=master, salt=t2, info="cleangeo-cstp-v1 kdf"||epoch||" s2c")
   c2s_iv  = HKDF-SHA256(secret=master, salt=t2, info="... c2s nonce", length=4)
   s2c_iv  = HKDF-SHA256(secret=master, salt=t2, info="... s2c nonce", length=4)
   ```
   Separate direction keys, separate nonce prefixes: a nonce reuse across
   directions is impossible by construction, not by discipline.
5. **CLIENT_FINISH.** `HMAC-SHA256(key=c2s, t2 || "client finished")`.
6. **SERVER_FINISH.** `HMAC-SHA256(key=s2c, t2 || "server finished")`.

Key confirmation proves each side derived the same keys. The client refuses to
accept a session without SERVER_FINISH (`allow_unconfirmed=True` exists only so
tests can isolate other properties).

### 4.1 Authentication properties, precisely

- The client authenticates the server by **pin comparison before any key use**,
  then by signature. A pin mismatch aborts with no keys derived.
- The server does **not** authenticate the client cryptographically. Client
  FINISH proves the client derived the keys, which an eavesdropper cannot. A
  client certificate or a per-client token would be needed for real client
  identity, and is **not implemented**.
- There is no anonymity: the server sees the client's IP regardless.

## 5. Record layer

```
FRAME = type:u8 || flags:u8 || counter:u64 || epoch:u32 || len:u16 || ciphertext
ciphertext = ChaCha20-Poly1305(key=direction_key, nonce=iv_prefix:4 || counter:u64,
                               aad=FRAME[0..13], plaintext)
```

- `flags` is 1 (reserved); any other bit is a protocol error.
- The header is authenticated as AAD but not encrypted. That is deliberate: the
  receiver needs the counter before decryption, and an attacker cannot forge a
  counter without the tag failing.
- `len` must equal the remaining bytes and be ≤ 16 KiB + 16.

**Order of operations on receive:** authenticate, *then* update the replay
window. An attacker who injects garbage must not be able to advance or poison
the window.

## 6. Replay protection

A 64-entry sliding window (RFC 6479 style), per direction, per epoch:

- counter greater than every counter seen → accepted, window slides;
- counter behind the window → rejected;
- counter inside the window and already set → rejected.

Window state is reset at every epoch change, which is safe *because* the epoch
is in the AAD: a frame from epoch *n* cannot be decrypted with epoch *n+1* keys.

## 7. Version negotiation and downgrade resistance

- The client offers exactly one version today; the message allows a range.
- The server must pick the highest mutually supported version. Picking lower is
  treated as a **downgrade attack** (`ERR_DOWNGRADE`), not as a preference.
- The check runs *before* the support check, so an unsupported low version
  cannot be misread as "unsupported" when it is actually a downgrade.
- The version is inside the signed transcript and inside the HKDF info string,
  so a rewrite of it invalidates both the signature and the keys.

This is a single-version protocol today. When a second version exists, the
downgrade argument needs to be re-reviewed: a real downgrade attack against a
server that supports v2 requires it to lie about v2 support, and the transcript
binding is what catches it.

## 8. Key rotation and forward secrecy

- **Ephemeral per session.** Each handshake generates fresh X25519 keys on both
  sides; the long-term Ed25519 key only signs. A later compromise of the
  identity key does not reveal past session keys.
- **In-session ratchet.** After `rekey_after` frames (default 2^20) either side
  derives epoch *n+1* from the same master secret with a different info string,
  and both reset counters and windows. The peer must ratchet on the same
  boundary; a frame from another epoch is refused.
- **Limitation:** this is a *hash ratchet from a fixed master*, not a full
  re-key. If the master secret leaks, all future epochs are derivable. It also
  does not limit the damage of a leaked *current* epoch key beyond one epoch.
  A DH-based re-key would be stronger; it is not implemented and should be part
  of the review.

## 9. Traffic analysis: what is not solved

The AEAD hides content, not shape. Unchanged by CSTP:

- **Sizes.** A DNS answer's size leaks the answer's type and rough size. No
  padding is applied. Adding padding costs bandwidth and battery; a study is
  needed before choosing a policy.
- **Timing.** Request/response timing leaks the page you are on.
- **Counts.** The number of queries leaks activity level.
- **Connection lifetime.** A long-lived session is itself a pattern.

Batching and timing normalisation are feasible but add latency to every
lookup. They are **not implemented**, and a truthful description of this system
says so: encrypted traffic does not hide metadata.

## 10. Error handling

Every error code in `ERROR_NAMES` destroys the session: `state → FAILED`,
`keys → None`. There is no partial recovery and no "skip the check" flag on the
production path. Codes: version, downgrade, pin mismatch, bad signature, bad
confirmation, replay, bad frame, bad state, expired, too large.

## 11. What must happen before production use

1. **Independent cryptographic review** of §§4–8 by someone who did not write
   it, with the reference implementation in hand.
2. **Formal analysis** of the handshake (a ProVerif/Tamarin model of the
   authentication and secrecy goals) — not started here.
3. **Interoperability tests** against an independent implementation.
4. **Decision on client authentication**, since possession-of-key is not
   identity.
5. **Padding/timing study** if traffic analysis resistance is a real goal.
6. **Key rotation and pin distribution** procedure, including what a pin
   rotation does to existing clients.

Until all six are done, CSTP stays inert and TLS 1.3 carries production
traffic.

## 12. Honest limitations

- Single version implemented; multi-version negotiation is untested.
- Client authentication is key possession only.
- No padding, no timing normalisation, no batching.
- Ratchet is master-derived, not DH-based.
- No formal model, no third-party implementation, no external review.
- No protection against a compromised endpoint.
- Test coverage is functional (26 tests) and adversarial in a narrow sense
  (tampering, replay, downgrade, wrong pin); it is not a security proof, and
  passing tests have never been evidence of security.
