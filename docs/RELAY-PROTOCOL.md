# VettID Relay Protocol

**Version:** 0.3.0 (draft)
**Status:** Pre-implementation draft for review

## 1. Purpose & design principles

The VettID Relay Protocol defines a minimal, vendor-neutral mailbox service for
exchanging **opaque, end-to-end-encrypted payloads** between VettID principals
(vaults, apps, and agents). A relay is dumb transport: it stores ciphertext it
cannot read, for recipients who alone decide who may deposit.

Design principles, in priority order:

1. **Zero relay trust.** The relay never holds keys to payload content, never
   parses payloads, and compromise of a relay is an availability event, never a
   confidentiality or integrity event.
2. **Recipient-sovereign authorization.** Only the mailbox owner issues
   permission to deposit, via tokens it signs with its own key. The relay
   enforces the owner's decisions; it does not make them.
3. **Implementation-agnostic.** Any conforming server — a Go binary with SQLite,
   a service on AWS, a future home appliance companion — is a valid relay.
4. **Boring by construction.** No clustering, no consensus, no federation in v1.
   Scale is achieved by running more relays and assigning mailboxes to them.

Conformance keywords MUST, SHOULD, MAY are per RFC 2119.

## 2. Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Identity & signing | Ed25519 (RFC 8032) |
| Deposit tokens | PASETO v4.public (Ed25519-signed) |
| Hashing | SHA-256 |
| Message IDs | ULID (Crockford base32, 26 chars) |
| Transport | HTTPS (TLS ≥ 1.2); WebSocket over TLS for streaming collect |

All base64 in this spec is standard RFC 4648 base64 **with** padding unless
stated otherwise. All timestamps are RFC 3339 UTC (`2026-06-10T12:00:00Z`).

## 3. Identities and mailbox IDs

### 3.1 Relay keypair

Every principal that owns a mailbox holds a dedicated Ed25519 keypair, the
**relay keypair**. It is a transport-layer identity only:

- It MUST NOT be the principal's protean credential key or any E2E messaging key.
- It SHOULD be rotatable without affecting E2E key material (see §8.3).
- Vault-side keys MUST be generated and held inside the vault's trust boundary.
  App-side keys SHOULD be held in a platform keystore.

### 3.2 Mailbox ID derivation

```
mailbox_id = lowercase( base32_rfc4648( SHA-256(pubkey_raw_32_bytes) ) )
             with padding removed, truncated to 26 characters
```

This yields 130 bits of the hash — collision-resistant for any plausible
population, and self-authenticating: registration requires proving possession
of the corresponding private key, so no allocation authority exists.

A principal's full address is `mailbox_id@relay_base_url`. Address exchange
happens out of band (e.g., during VettID connection establishment) and is not
part of this protocol.

## 4. Authentication mechanisms

The protocol uses two mechanisms. Both are stateless; the relay holds no
sessions.

### 4.1 Signed requests (all authenticated routes)

Every authenticated request carries three headers:

| Header | Content |
|---|---|
| `X-VettID-Key` | base64(raw 32-byte Ed25519 public key) of the requester |
| `X-VettID-Timestamp` | RFC 3339 UTC timestamp of the request; MAY include fractional seconds (clients SHOULD send millisecond precision, see below) |
| `X-VettID-Sig` | base64(Ed25519 signature) over the request digest (below) |

**Canonical request digest:**

```
canonical = METHOD || "\n" || PATH || "\n" || timestamp || "\n" || hex(SHA-256(body))
digest    = SHA-256(canonical)
signature = Ed25519-Sign(requester_private_key, digest)
```

- `METHOD` is uppercase. `PATH` is the request path including the `/v1` prefix,
  excluding query string. For bodiless requests, `body` is the empty byte string
  (`hex(SHA-256(""))` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
- The relay MUST reject requests where |server_now − timestamp| > **90 seconds**
  (`code: timestamp_stale`).
- The relay MUST keep an in-memory replay cache of (key, signature) pairs for at
  least the freshness window and reject duplicates (`code: replay_detected`).
- The canonical string uses the `X-VettID-Timestamp` header value **verbatim**.
  Because the digest does not cover the query string and Ed25519 signatures are
  deterministic, two otherwise identical requests in the same second would
  collide in the replay cache (e.g. a long-poll re-issued immediately, §6.2).
  Clients SHOULD therefore send fractional seconds (millisecond precision);
  relays MUST accept them.
- For **owner routes** (collect, ack, denylist, rotate), the relay MUST verify
  that `X-VettID-Key` equals the registered pubkey of the mailbox being operated
  on.
- For **deposit**, `X-VettID-Key` MUST equal the `sub` of the presented deposit
  token (sender binding, §5.3) — except for one-shot open tokens (§5.6), where
  the signer becomes the depositor.

### 4.2 Deposit tokens

Permission to deposit into a mailbox is granted exclusively by a **deposit
token**: a PASETO v4.public token signed by the mailbox owner's relay key.
Defined in §5.

## 5. Deposit tokens

### 5.1 Format

PASETO v4.public. The payload is a compact JSON object (no insignificant
whitespace). The footer and implicit assertion are empty in v1.

### 5.2 Claims

| Claim | Req | Meaning |
|---|---|---|
| `iss` | MUST | mailbox_id of the issuing (recipient) mailbox |
| `sub` | MUST | base64 raw pubkey of the authorized sender's relay key; the literal `*` only in open tokens (§5.6) |
| `aud` | MUST | base URL of the relay the token is valid for (exact match) |
| `iat` | MUST | issuance time |
| `exp` | MUST | expiry. SHOULD be ≤ 30 days for standing (connection) tokens; SHOULD be ≤ 5 minutes for one-shot tokens |
| `jti` | MUST | unique token ID (ULID recommended); the revocation handle |
| `scope` | MUST | `deposit` (sender-bound) or `deposit_open` (one-shot open token, §5.6) |
| `quota` | MAY | `{ "msgs": n, "bytes": n }` — cap on this token's total deposits; relay enforces best-effort per relay instance |

**Lifetime cap.** A relay MAY refuse tokens whose `exp − iat` exceeds its
`max_token_lifetime_seconds` (`token_invalid`) and MUST advertise that limit at
registration (§6.1). This is what bounds denylist retention (§5.5). The limit
is relay policy: the 30-day guidance above is for standing tokens, while
applications MAY mint rarely used, low-quota tokens with longer lifetimes
(e.g. a connection's reconnect token, up to about a year) where the relay
allows it. Long-lived tokens SHOULD carry a small `quota`.

**Clock skew.** `iat ≤ now` is checked strictly. Issuers SHOULD backdate `iat`
by up to 30 seconds if their clock may run ahead of the relay's.

### 5.3 Relay-side validation order

On `POST /v1/mailbox/{mailbox_id}` the relay MUST first enforce the body size
limit (`payload_too_large`, §8.5), then verify, in order:

1. Mailbox exists → else `mailbox_unknown`
2. Token parses as PASETO v4.public and its signature verifies against the
   **registered pubkey of `{mailbox_id}`** → else `token_invalid`
3. `iss` == `{mailbox_id}` → else `token_invalid`
4. `aud` == this relay's configured base URL → else `token_invalid`
5. `iat` ≤ now < `exp` → else `token_expired`
6. `jti` not in mailbox denylist AND `sub` not in mailbox denylist
   → else `token_revoked`; for open tokens (§5.6), `jti` not already consumed
   → else `token_used`
7. Request signature (§4.1) verifies AND `X-VettID-Key` == token `sub`
   (open tokens: the signature alone) → else `signature_invalid`
8. Quota counters (token quota if present, mailbox quota) not exceeded
   → else `quota_exceeded`

A leaked token without the sender's private key MUST be unusable (step 7).

### 5.4 Token transport

The token is presented in the `Authorization` header:

```
Authorization: VettID-Deposit <paseto-token>
```

### 5.5 Revocation

Owners revoke by `jti` (one token) or by `sub` (everything a sender holds):

```
POST /v1/mailbox/denylist            (owner-signed, §4.1)
{ "revoke": [ {"kind":"jti","value":"01J..."},
              {"kind":"sub","value":"<base64 pubkey>"} ] }
→ 204
```

The relay MUST retain each denylist entry at least until the latest possible
expiry of any token it could match; entries MAY then be garbage-collected.
Issuers SHOULD bound token lifetimes (§5.2) precisely so that denylists stay
small. A `sub` entry also blocks tokens minted for that sender *after* the
revocation, until the entry expires.

### 5.6 One-shot open tokens (first contact)

A sender-bound token needs the sender's relay key in advance, which first
contact (scanning a QR code, a pairing code, an invitation) cannot provide.
For that case an owner MAY mint a **one-shot open token**:

- `scope` = `deposit_open`, `sub` = `*`;
- `exp − iat` MUST be ≤ `open_token_max_lifetime_seconds`, a relay policy
  value advertised at registration (default **600 s**; relays MAY allow longer
  for remote invitations — RECOMMENDED ≤ 7 days);
- it permits **exactly one** deposit: the relay MUST record the `jti` as
  consumed on the first successful deposit and retain that record until `exp`
  (a second use → `409 token_used`);
- the deposit request MUST still be signed (§4.1) by *some* Ed25519 key; that
  key becomes the deposit's `sender` (§6.3), so the recipient learns the first
  contact's relay key and can answer with a normal sender-bound token.

Open tokens are bearer capabilities: whoever holds one can deposit one
message. Owners SHOULD keep them as short-lived as the use allows (minutes for
an in-person QR code; longer only for invitations sent through other
channels) and deliver them only out of band — typically alongside a claim id
(§6.9) whose content is committed to by hash. Applications SHOULD treat a
contact arriving through a long-lived open token as unconfirmed until the
owner approves it. Revocation by `jti` works as for any token.

## 6. Endpoints

Base path `/v1`. All bodies are `application/json` unless noted. Payloads are
base64-encoded opaque bytes; the relay MUST NOT parse, transform, or log them.

### 6.1 Register mailbox

```
POST /v1/register                    (signed request; key being registered)
{ "pubkey": "<base64 raw ed25519 pubkey>" }
→ 201 { "mailbox_id": "...",
        "limits": { "max_payload_bytes": 262144,
                    "message_ttl_seconds": 1209600,
                    "visibility_timeout_seconds": 60,
                    "max_token_lifetime_seconds": 34560000,
                    "open_token_max_lifetime_seconds": 604800,
                    "max_claim_bytes": 16384,
                    "claim_ttl_seconds": 604800,
                    "max_blob_bytes": 8388608,
                    "blob_ttl_seconds": 604800 } }
```

(`max_blob_bytes` and `blob_ttl_seconds` are present only if the relay supports
blob transfer, §6.8.)

- `X-VettID-Key` MUST equal `pubkey` (proof of possession via the request
  signature).
- Re-registering an existing pubkey is idempotent → `200` with same body.
- Registration is open by default. Relay operators MAY require an invite token
  (operator policy; mechanism reserved for a future minor version).

### 6.2 Deposit

```
POST /v1/mailbox/{mailbox_id}        (deposit token §5 + signed request §4.1)
{ "payload": "<base64 ciphertext>" }
→ 201 { "msg_id": "<ULID>" }
```

- Payload after base64 decoding MUST NOT exceed `max_payload_bytes`
  (default **262,144 bytes**) → else `payload_too_large`.
- Larger content uses the **claim-check convention**: the deposited payload is a
  small encrypted envelope pointing at externally stored ciphertext. Blob
  storage is explicitly out of protocol scope.
- The relay assigns the ULID; per-mailbox ULID order is arrival order.
- **Wake-on-deposit:** if the recipient has a parked long-poll request (§6.3) or
  an open WebSocket (§6.4), the relay SHOULD deliver the message to it
  immediately upon successful deposit, without waiting for a poll interval.
  Relays SHOULD target sub-second deposit-to-delivery latency for connected
  collectors; polling loops or batch scans that add fixed delay between deposit
  and delivery SHOULD NOT be used on this path. Clients with always-on
  connectivity SHOULD re-issue their long-poll immediately after each collect
  response (or use WebSocket) so no delivery gap exists on the receiver side.

### 6.3 Collect (long-poll)

```
GET /v1/mailbox?wait=25&max=32       (owner-signed)
→ 200 { "messages": [ { "msg_id": "<ULID>",
                        "deposited_at": "<RFC3339>",
                        "sender": "<base64 depositor relay pubkey>",
                        "payload": "<base64>" }, ... ] }
```

- `sender` is the key that signed the deposit request: the token's `sub` for
  sender-bound tokens, the signer for open tokens (§5.6). The relay vouches
  only that this key signed the deposit; the payload's own E2E authentication
  remains the authority on who wrote it.
- `wait` defaults to 0 and `max` to 32; larger values are clamped to the caps.
- Returns up to `max` (cap 100) oldest messages that are unexpired and not
  currently leased; returned messages become leased for
  `visibility_timeout_seconds`.
- If none are available, the relay parks the request up to `wait` seconds
  (cap 25), returning early if a deposit arrives; on timeout returns
  `{ "messages": [] }`.
- **Delivery is at-least-once.** A message not acked within its lease reappears
  in later collects. Receivers MUST deduplicate by `msg_id`.

### 6.4 Collect (WebSocket)

```
GET /v1/mailbox/ws                   (owner-signed at upgrade)
```

Server frames: `{ "msg_id", "deposited_at", "sender", "payload" }` — same
lease semantics. Client frames: `{ "ack": "<msg_id>" }`. WebSocket support is
OPTIONAL for relays and clients; long-poll is the mandatory baseline.

### 6.5 Ack

```
DELETE /v1/mailbox/{msg_id}          (owner-signed)
→ 204
```

Always `204`: whether the message existed, was already acked, or belongs to
another mailbox (in which case nothing happens). A uniform answer means ack
can't be used to probe which message ids exist. (0.2.0 returned 404 for
another mailbox's message, which was itself an existence oracle.)

### 6.6 Denylist

See §5.5.

### 6.7 Key rotation

```
POST /v1/mailbox/rotate              (signed by CURRENT registered key)
{ "new_pubkey": "<base64>",
  "new_key_proof": "<base64 sig by new key over current mailbox_id>" }
→ 200 { "mailbox_id": "<new mailbox_id>" }
```

Rotation creates the successor mailbox and marks the old one for deletion after
a grace period (relay config, default 7 days, during which both collect).
Because mailbox_id is key-derived, rotation changes the address; owners are
responsible for re-issuing deposit tokens and notifying connections over E2E
channels. Tokens issued under the old key die with it — this is a feature.

### 6.8 Blob transfer (files up to relay blob limit)

A relay MAY support ephemeral blob transfer for payloads larger than
`max_payload_bytes` (e.g., images and small files; intended ceiling ~5 MB of
plaintext plus encryption overhead). Blob support is OPTIONAL; relays that
support it advertise `max_blob_bytes` in the registration `limits` object.
Blobs reuse the existing authorization machinery — no new token type.

```
PUT /v1/blob/{mailbox_id}            (deposit token §5 + signed request §4.1)
Content-Type: application/octet-stream
<raw ciphertext bytes, streamed>
→ 201 { "blob_id": "<ULID>", "expires_at": "<RFC3339>" }
```

- Authorization is identical to deposit (§5.3, all 8 steps), with byte-size
  counted against the token's `quota.bytes` if present and against the
  mailbox's blob storage cap.
- Body MUST NOT exceed `max_blob_bytes` (default **8,388,608 bytes**); relays
  MUST enforce this limit during streaming, not after buffering
  → `payload_too_large`.
- For the signed-request digest (§4.1), `hex(SHA-256(body))` is computed over
  the raw ciphertext bytes.
- Blobs SHOULD be stored outside the message database (e.g., as files on disk)
  and MUST NOT be parsed or logged.

```
GET /v1/blob/{blob_id}               (owner-signed; recipient mailbox only)
→ 200 application/octet-stream
```

- Only the owner of the mailbox the blob was deposited to may fetch it. There
  are no public or shareable URLs. Unauthorized or unknown blob ids return the
  same error (`blob_unknown`) — no existence oracle.

```
DELETE /v1/blob/{blob_id}            (owner-signed)
→ 204    (idempotent)
```

- **TTL:** blobs are a transfer mechanism, not storage. Default
  `blob_ttl_seconds` = 604800 (7 days); the sweeper deletes expired blobs.
  Recipients SHOULD fetch promptly and persist the content in their own
  storage, then DELETE.

**Claim-check flow (informative).** The intended end-to-end pattern: the
sender generates a fresh symmetric key, encrypts the file
(XChaCha20-Poly1305 recommended), uploads the ciphertext via `PUT /v1/blob`,
then sends an ordinary mailbox message (§6.2) whose end-to-end-encrypted
payload carries `{ blob_id, key, content_hash, filename, mime, size }`. The
relay observes only ciphertext and sizes; the recipient cannot fetch a blob it
hasn't been told about, and verifies `content_hash` after decryption. Blob
metadata (filename, type) MUST travel only inside the E2E message, never in
relay-visible fields.

Additional error code: `blob_unknown`.

### 6.9 Claims (bootstrap bundles for first contact)

A **claim** is a small blob an owner leaves on the relay for someone who does
not yet have a token — e.g. the key bundle behind a QR code (PQC-MIGRATION
§6.5: the QR carries `{claim_id, bundle_hash}`, never the bundle itself).

```
PUT /v1/claim                        (signed by a registered mailbox key, §4.1)
Content-Type: application/octet-stream
X-VettID-Claim-TTL: <seconds>        (optional, ≤ claim_ttl_seconds; default 900)
<raw bytes, ≤ max_claim_bytes>
→ 201 { "claim_id": "<26-char lowercase base32 of 128 random bits>",
        "expires_at": "<RFC3339>" }

GET /v1/claim/{claim_id}             (unauthenticated; rate-limited)
→ 200 application/octet-stream       (single fetch: the claim is deleted)

DELETE /v1/claim/{claim_id}          (signed by the creating key)
→ 204                                (idempotent)
```

- `claim_ttl_seconds` (advertised at registration) is relay policy: the
  maximum TTL a creator may request. Default 900 s; relays MAY allow longer
  for remote invitations (RECOMMENDED ≤ 7 days).
- Claims are **single-fetch**: the first successful GET deletes the claim.
  Unknown, expired, already-fetched and never-existed claims all return the
  same `404 claim_unknown`.
- The relay vouches for nothing about the content; integrity comes from the
  hash commitment carried out of band. Content SHOULD be public key material
  only.
- Claim ids MUST be generated by the relay from a CSPRNG and MUST NOT be logged.
  Claims count against the creating mailbox's storage quota; relays SHOULD rate
  limit GETs per client network (IPv4 address / IPv6 /64) to resist guessing
  and scraping.

## 7. Errors, limits, versioning

### 7.1 Error body

```
{ "code": "<canonical_code>", "message": "<human readable>", "retry_after": <seconds, optional> }
```

Canonical codes and their HTTP statuses:

| Code | HTTP | Meaning |
|---|---|---|
| `bad_request` | 400 | malformed JSON, base64, header or parameter |
| `signature_invalid` | 401 | request signature missing, wrong, or not the required key |
| `timestamp_stale` | 401 | timestamp outside the freshness window |
| `replay_detected` | 401 | (key, signature) already seen |
| `token_invalid` | 401 | token malformed, bad signature, wrong `iss`/`aud`/`scope`, lifetime too long |
| `token_expired` | 401 | outside `iat`..`exp` |
| `token_revoked` | 403 | `jti` or `sub` on the owner's denylist |
| `mailbox_unknown` | 404 | no such mailbox (or not yours — indistinguishable) |
| `blob_unknown` | 404 | no such blob for this owner |
| `claim_unknown` | 404 | no such claim (unknown, expired or already fetched) |
| `not_found` | 404 | no such route |
| `token_used` | 409 | one-shot open token already consumed (§5.6) |
| `payload_too_large` | 413 | body over the advertised limit |
| `quota_exceeded` | 429 | token or mailbox quota exhausted |
| `rate_limited` | 429 | slow down; see `retry_after` |
| `internal` | 500 | relay fault |

### 7.2 Rate limiting

Limits are relay policy, not protocol constants. The protocol contract: a
relay signalling overload MUST use `429` + `rate_limited` and SHOULD include
`retry_after`. Clients MUST honor `retry_after` and MUST implement exponential
backoff with jitter on `429` and `5xx`.

### 7.3 Versioning

The URL prefix (`/v1`) is the major version. Backward-compatible additions
(new optional fields, new endpoints) bump the spec's minor version without a
prefix change. This document carries a semver and a changelog (§10).

## 8. Security considerations

1. **Payload confidentiality/integrity is out of scope by design** — payloads
   MUST already be end-to-end encrypted and authenticated by the VettID
   messaging layer. The relay's authorization controls exist for abuse and
   availability protection, not confidentiality.
2. **Metadata.** The relay necessarily observes deposit timing, payload sizes,
   sender relay-keys, and recipient mailboxes. Operators MUST NOT log payloads;
   SHOULD log only msg_ids, sizes, and error codes; and SHOULD minimize
   retention of sender/recipient correlation data. Traffic-analysis resistance
   is a non-goal of v1 and is honestly disclosed as such.
3. **Sender binding** (§5.3 step 7) means token theft alone is harmless;
   compromise requires the sender's private key, at which point the sender's
   own E2E identity is the larger problem.
4. **Replay** is bounded by the 90 s freshness window plus the replay cache
   (§4.1); deposits replayed outside the window fail on timestamp; inside it,
   on the cache. Duplicate deposits that do occur are absorbed by receiver-side
   ULID dedupe.
5. **DoS.** Body-size limits MUST be enforced before signature verification;
   per-IP rate limits SHOULD apply before token parsing; signature verification
   (cheap for Ed25519) precedes any database write.
6. **Relay compromise** yields: stored ciphertext, registration pubkeys,
   denylists, and the ability to drop or delay messages. It yields no plaintext
   and no ability to forge deposits as an authorized sender (no private keys on
   the relay). Recovery = stand up a new relay, re-register, re-issue tokens.
7. **No existence oracles.** Unauthorized ack/collect/denylist calls return the
   same error whether or not the target exists.
8. **Blobs** inherit the deposit trust model: same token validation, same sender
   binding. Blob content limits MUST be enforced while streaming to prevent
   memory exhaustion; blob storage MUST be capped per mailbox; and blob
   metadata (filename, MIME type) MUST only ever appear inside E2E-encrypted
   message payloads, never in relay-visible requests, storage, or logs.

## 9. Test vectors

Keys below use fixed seeds (all-0x01 and all-0x02 bytes). **Test use only.**

### 9.1 Keys and mailbox IDs

```
recipient seed   (b64): AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
recipient pubkey (b64): iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=
recipient mailbox_id  : gr2q7gf5lh6pzfdnurnkvputhp

sender seed      (b64): AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
sender pubkey    (b64): gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=
sender mailbox_id     : ni4ahvpqlgicuhdnv66jxjdssi
```

### 9.2 Deposit token

Claims (exact signed bytes — compact JSON, this key order):

```
{"iss":"gr2q7gf5lh6pzfdnurnkvputhp","sub":"gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=","aud":"https://relay.example.vettid.org","iat":"2026-06-10T00:00:00Z","exp":"2026-07-10T00:00:00Z","jti":"01JXAMPLE0000000000000000","scope":"deposit"}
```

Token (PASETO v4.public, signed by recipient key):

```
v4.public.eyJpc3MiOiJncjJxN2dmNWxoNnB6ZmRudXJua3ZwdXRocCIsInN1YiI6ImdUbDNEcWg5RjE5V28xUm13MHgrek11TmlwRzA3amVpWGZZUFc0L0pzNVE9IiwiYXVkIjoiaHR0cHM6Ly9yZWxheS5leGFtcGxlLnZldHRpZC5vcmciLCJpYXQiOiIyMDI2LTA2LTEwVDAwOjAwOjAwWiIsImV4cCI6IjIwMjYtMDctMTBUMDA6MDA6MDBaIiwianRpIjoiMDFKWEFNUExFMDAwMDAwMDAwMDAwMDAwMCIsInNjb3BlIjoiZGVwb3NpdCJ9rWQjEmgif2o_c9SNTUXzHPPLWKZCPMAPUk3VPpbWkTIY0pfihNHpVZeX-YDM35FN_u1FVYPHj4BrO4sGJQj6BA
```

(Note: PASETO signatures are deterministic for Ed25519, so a conforming
implementation signing these exact payload bytes with this key MUST reproduce
this token byte-for-byte.)

### 9.3 Signed deposit request

```
method                : POST
path                  : /v1/mailbox/gr2q7gf5lh6pzfdnurnkvputhp
body                  : {"payload":"b3BhcXVlLWNpcGhlcnRleHQtYnl0ZXM="}
sha256(body) hex      : 0237514b3df17b219036f1b8fa6ca70d4ca597eb630933841707380055d7e12a

canonical string (one line; \n are literal newline bytes):
POST\n/v1/mailbox/gr2q7gf5lh6pzfdnurnkvputhp\n2026-06-10T12:00:00Z\n0237514b3df17b219036f1b8fa6ca70d4ca597eb630933841707380055d7e12a

sha256(canonical) b64 : l+mc5XMNElCBLC49xJH4Lc8LHEAlAK1HunqaS+LZ33k=

X-VettID-Key          : gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=
X-VettID-Timestamp    : 2026-06-10T12:00:00Z
X-VettID-Sig          : pOZT7Pb981+3K4wWv6Zryb43miSLBfKdCZ4Wc/qNzQyxFtOPrsSSkK1Gj5mF+Zb3z3yC4Bi7AyjIyVkeN+nsDA==
```

NOTE: the canonical string is exactly
`POST` + `\n` + path + `\n` + timestamp + `\n` + lowercase hex of SHA-256(body);
the signature is Ed25519 over SHA-256(canonical).

## Appendix A (informative) — Mobile wake via push gateway

This appendix describes the intended pattern for delivering to mobile apps
that cannot maintain persistent connections (iOS especially). It is
**informative**: the push gateway is a separate service with its own API, and
nothing in it modifies the relay protocol. Relays remain push-unaware and
vendor-neutral; no relay operator ever holds APNs/FCM credentials.

The pattern exploits a property of the VettID message flow: every deposit into
an app's mailbox originates from the user's own vault (apps communicate only
with their OwnerSpace; the vault handles MessageSpace). The vault is therefore
always in a position to trigger a wake-up after depositing:

```
peer ──deposit──▶ relay ──collect──▶ vault          (vault is always connected)
vault ──deposit──▶ relay                            (reply/notification for app)
vault ──"wake ref X"──▶ push gateway ──empty push──▶ device
device (NSE / FCM handler) ──collect──▶ relay ──▶ decrypt locally
```

Properties:

- **Pushes carry no content** — no message data, no sender, no mailbox id; at
  most an opaque wake reference. On iOS, a Notification Service Extension
  collects from the relay and decrypts locally before the notification is
  shown, so plaintext never transits Apple or Google infrastructure.
- **The gateway holds APNs/FCM credentials and an opaque mapping** from wake
  references to push tokens. The app registers its push token with its vault
  over OwnerSpace; the vault registers an opaque reference with the gateway.
  The gateway learns neither mailbox ids nor message timing beyond the wakes
  it is asked to send.
- **Connected clients never need it**: a foregrounded app or an always-on
  desktop/agent uses long-poll/WebSocket and achieves sub-second delivery via
  wake-on-deposit (§6.2). Android implementations MAY use a persistent
  background service in lieu of the gateway, though FCM via the gateway is
  recommended for battery and Doze-mode resilience.

The push gateway API is specified separately.

## 10. Changelog

- **0.3.0** — first contact: one-shot open deposit tokens (§5.6) and single-fetch
  claims for bootstrap bundles (§6.9), with maximum lifetimes as advertised
  relay policy (short by default, up to ~7 days for remote invitations); collect results carry the depositor's
  `sender` key (§6.3, §6.4); fractional-second timestamps (§4.1); ack always
  `204` (§6.5, removes an existence oracle); token lifetime cap advertised at
  registration and `sub`-revocation semantics; long-lived low-quota tokens
  (e.g. reconnect) allowed by relay policy (§5.2, §5.5); size check before
  token validation (§5.3); collect defaults; complete error-code table with
  HTTP statuses (§7.1). All additive for clients; relays must implement the new
  endpoints and fields.
- **0.2.0** — wake-on-deposit latency requirements (§6.2); OPTIONAL blob
  transfer endpoints with claim-check flow (§6.8) and blob limits advertised
  at registration (§6.1); `blob_unknown` error code; blob security
  considerations (§8.8); informative push-gateway appendix (Appendix A).
- **0.1.0** — initial draft: registration, deposit tokens (PASETO v4.public,
  sender-bound), deposit/collect/ack, denylist revocation, key rotation, test
  vectors.
