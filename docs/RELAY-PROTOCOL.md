# VettID Relay Protocol

**Version:** 0.6.0 (draft)
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
- For **owner routes** (collect, ack, denylist, rotate, delete), the relay
  MUST verify that `X-VettID-Key` equals the registered pubkey of the mailbox
  being operated on.
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
by up to 60 seconds if their clock may run ahead of the relay's (one-shot open
tokens by at most half their lifetime). Lifetimes are measured from the
backdated `iat`.

### 5.3 Relay-side validation order

On `POST /v1/mailbox/{mailbox_id}` the relay MUST first enforce the body size
limit (`payload_too_large`, §8.5), then verify, in order:

1. Mailbox exists → else `mailbox_unknown`
2. Token parses as PASETO v4.public and its signature verifies against the
   **registered pubkey of `{mailbox_id}`** → else `token_invalid`
3. `iss` == `{mailbox_id}` → else `token_invalid`
4. `aud` == this relay's configured base URL → else `token_invalid`
5. `iat` ≤ now < `exp` → else `token_expired`
6. `jti` not in mailbox denylist AND `sub` not in mailbox denylist AND, if
   the mailbox id was deleted before (§6.10), `iat` ≥ its tokens-not-before
   time → else `token_revoked`; for open tokens (§5.6), `jti` not already
   consumed → else `token_used`
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
revocation, until the entry expires. A denylist ends with its mailbox
(deleted, §6.10, or removed at the end of its rotation grace, §6.7); the
tombstone the mailbox leaves keeps every token minted before then refused
if its key ever registers again, so no revocation is undone that way.

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
  (a second use → `409 token_used`); a deposit rejected for another reason
  (bad signature, quota) does not consume it;
- it authorizes `POST /v1/deposit` only — **not** blob upload (§6.8), so a
  bearer token cannot place a large blob (`token_invalid`);
- the deposit request MUST still be signed (§4.1) by *some* Ed25519 key; that
  key becomes the deposit's `sender` (§6.3), so the recipient learns the first
  contact's relay key and can answer with a normal sender-bound token.

Open tokens are bearer capabilities: whoever holds one can deposit one
message. Owners SHOULD keep them as short-lived as the use allows (minutes for
an in-person QR code; longer only for invitations sent through other
channels) and deliver them only out of band — typically alongside a claim id
(§6.9) whose content is committed to by hash. Applications SHOULD treat a
contact arriving through a long-lived open token as unconfirmed until the
owner approves it. Revocation by `jti` works as for any token. Per-sender
rate limits (§7.2) key on the open token's `jti`, since the token has no
fixed sender.

## 6. Endpoints

Base path `/v1`, except the web endpoints (§6.11). All bodies are `application/json` unless noted. Payloads are
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
                        "jti": "<jti of the deposit token>",
                        "payload": "<base64>" }, ... ] }
```

- `sender` is the key that signed the deposit request: the token's `sub` for
  sender-bound tokens, the signer for open tokens (§5.6). The relay vouches
  only that this key signed the deposit; the payload's own E2E authentication
  remains the authority on who wrote it.
- `jti` (0.4.0) is the `jti` of the deposit token the message was accepted
  under, so an owner holding several tokens for one sender (e.g. a standing
  and a reconnect token) can tell which was used. Like `sender`, it is
  visible only to the mailbox owner. Messages stored by a pre-0.4 relay MAY
  omit it; clients MUST tolerate its absence.
- `wait` defaults to 0 and `max` to 32; larger values are clamped to the caps.
- Returns up to `max` (cap 100) oldest messages that are unexpired and not
  currently leased; returned messages become leased for
  `visibility_timeout_seconds`.
- If none are available, the relay parks the request up to `wait` seconds
  (cap 25), returning early if a deposit arrives; on timeout returns
  `{ "messages": [] }`. If the mailbox is deleted meanwhile (§6.10), the
  parked request ends at once with `404 mailbox_unknown`.
- **Delivery is at-least-once.** A message not acked within its lease reappears
  in later collects. Receivers MUST deduplicate by `msg_id`.

### 6.4 Collect (WebSocket)

```
GET /v1/mailbox/ws                   (owner-signed at upgrade)
```

Server frames: `{ "msg_id", "deposited_at", "sender", "jti", "payload" }` — same
lease semantics. Client frames: `{ "ack": "<msg_id>" }`. WebSocket support is
OPTIONAL for relays and clients; long-poll is the mandatory baseline. When the
mailbox is deleted (§6.10) the relay closes the session with close code
**4404** and reason `mailbox_unknown`.

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
When the relay removes the old mailbox at the end of the grace period it
leaves the same tombstone as a deletion (§6.10), with the removal time in
place of the deletion time: if the old key registers again, tokens issued
before the removal time plus 90 seconds are refused (`token_revoked`), so
the old mailbox's revocations and used one-shot tokens cannot come back.
Deleting the successor (§6.10) also deletes an old mailbox still in its grace
period; deleting the old mailbox (signed by the old key) ends only its own
grace.

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
PUT /v1/claim                        (signed by a registered mailbox key, §4.1;
PUT /v1/claim/ttl/{seconds}           TTL default 900 s, or {seconds} in
                                      [1, claim_ttl_seconds], canonical decimal)
Content-Type: application/octet-stream
<raw bytes, 1..max_claim_bytes>
→ 201 { "claim_id": "<26-char lowercase base32 of 128 random bits>",
        "expires_at": "<RFC3339>" }

GET /v1/claim/{claim_id}             (unauthenticated; rate-limited)
→ 200 application/octet-stream       (single fetch: the claim is deleted)

DELETE /v1/claim/{claim_id}          (signed by the creating key)
→ 204                                (idempotent)
```

- `claim_ttl_seconds` (advertised at registration) is relay policy: the
  maximum TTL a creator may request. Default 900 s; relays MAY allow longer
  for remote invitations (RECOMMENDED ≤ 7 days). The TTL is carried in the
  path so the request signature (§4.1) covers it; an out-of-range or
  non-canonical value is `bad_request` (never clamped). The default is
  min(900 s, `claim_ttl_seconds`). Empty claims are `bad_request`.
- Claims are **single-fetch**: the first successful GET deletes the claim.
  Unknown, expired, already-fetched and never-existed claims all return the
  same `404 claim_unknown`.
- The relay vouches for nothing about the content; integrity comes from the
  hash commitment carried out of band. Content SHOULD be public key material
  only.
- Claim ids MUST be generated by the relay from a CSPRNG and MUST NOT be logged.
  Claims count against the creating mailbox's blob storage cap (together
  with its blobs, §6.8); relays SHOULD rate
  limit GETs per client network (IPv4 address / IPv6 /64) to resist guessing
  and scraping.
- A claim GET MUST NOT be retried automatically by clients: if the response
  is lost, the claim is already gone. Recover by asking the owner for a new
  claim.

### 6.10 Mailbox deletion (0.5.0)

```
DELETE /v1/mailbox                   (owner-signed, §4.1; no body)
→ 204
```

The owner deletes its mailbox — the one whose id derives from
`X-VettID-Key` — and everything in it. The request has no body (a body is
`bad_request`); the signature over `DELETE` and the path `/v1/mailbox` is the
whole authorization, so a signed ack (`DELETE /v1/mailbox/{msg_id}`) can never
be replayed as a deletion.

- **What is deleted:** the registration, every message (leased or not), the
  denylist, token quota counters and consumed open-token records, every blob
  deposited to it (§6.8) and every claim it created (§6.9). Every mailbox
  rotated into this one and still in its grace period (§6.7) is deleted with
  it (recursively), so tokens issued under an earlier key stop working too.
- **Afterwards** the mailbox id behaves as never registered: deposits and blob
  uploads get `mailbox_unknown` (§5.3 step 1), owner routes get
  `mailbox_unknown`, claims it created are `claim_unknown`. A relay MUST
  refuse deposits, blob uploads and claim creation from the moment it answers
  `204`, on every server instance that shares the mailbox. A collector parked
  on the mailbox gets `mailbox_unknown` (§6.3); a WebSocket session is closed
  with 4404 (§6.4). A multi-instance relay MAY let other instances answer
  owner requests of the deleted key briefly (at most a few minutes) as for an
  empty mailbox.
- **Idempotent:** `204` whether or not the mailbox existed — never
  registered, already deleted, or past its rotation grace. Only the key's
  holder can call it, so the answer reveals nothing.
- **Re-registration.** The key MAY register again (§6.1, `201`): it gets a
  fresh, empty mailbox at the same id. Because the denylist and the
  consumed-token records went with the old mailbox, the relay keeps a
  **tombstone** for the id: its **tokens-not-before** time is the deletion
  time plus the 90-second freshness window (§4.1; it covers an owner clock
  running ahead of the relay's). Every token with `iat` before it is refused
  with `token_revoked` (§5.3 step 6), whatever its `exp`, so no token minted
  before the deletion — and no revocation or one-shot use the deletion
  erased — can become valid again. The tombstone is kept until every such
  token has expired: at least `max(max_token_lifetime_seconds,
  open_token_max_lifetime_seconds)` after the tokens-not-before time (the
  same bound as denylist entries, §5.5). An owner that re-registers a deleted
  key MUST mint new tokens with `iat` at least 90 seconds after the deletion
  (and SHOULD NOT backdate them across it, §5.2). Registering a new key is
  simpler and RECOMMENDED: the tombstone then never matters. A mailbox
  removed at the end of its rotation grace leaves the same tombstone, timed
  from its removal (§6.7).
- **Rotation.** Rotating into a deleted key's id (§6.7) is a re-registration:
  the successor starts empty and carries the tombstone's tokens-not-before.
- **Timing.** Deletion is immediate; nothing waits for the message TTL. Clients
  SHOULD treat a lost response as unknown and repeat the request (it is
  idempotent and retryable on `429`/`5xx`, §7.2).

### 6.11 Web endpoints (0.6.0)

Outside `/v1`, every relay serves a few fixed documents, built into the relay
software, so that invitation links work on any relay — VettID's, a
self-hosted one or a home appliance — with nothing from vettid.org
(VAULT-MESSAGING §6.4, "Invitation URL"):

| Path | `Content-Type` | Content |
|---|---|---|
| `/connect` | `text/html; charset=utf-8` | the invitation landing page |
| `/.well-known/assetlinks.json` | `application/json` | Android Digital Asset Links for the VettID app |
| `/robots.txt` | `text/plain; charset=utf-8` | `User-agent: *`, `Allow: /.well-known/`, `Disallow: /` |
| `/.well-known/apple-app-site-association` | — | reserved for iOS universal links; not served yet (the ordinary `404`) |

An invitation URL is `<relay>/connect#<link>`. The payload is the URL
fragment, which browsers never send, so the relay never receives it. The
rules below keep the page from leaking it, and make probing these paths
(scanners request them within minutes of a URL appearing in public) cheap
for the relay and uninformative for the prober.

**Fixed responses.** These rules are normative for every path in the table.

1. **Same bytes for every request.** Each document is fixed for the life of
   the relay process: the same status, body and headers for every request,
   except `Date`. Nothing in a response depends on the request — not the
   query string (ignored), the path's spelling, request headers, cookies or
   the client's address. A relay MUST NOT set cookies or `Vary`.
2. **Exact paths, no redirects.** Only the exact paths above are served.
   Every other spelling — `/connect/`, `/connect/x`, `/Connect`,
   percent-encoded forms, `//connect`, dot segments — gets the relay's
   ordinary `404` `not_found` (§7.1), byte-for-byte the response to any
   other unknown path. A relay MUST NOT redirect (no `301`/`308` to a
   cleaned or slash-appended path); this holds for every relay path,
   `/v1` included.
3. **Methods.** `GET` and `HEAD`. `HEAD` returns the `GET` headers without
   the body. Any other method gets `405` with `Allow: GET, HEAD` and an empty
   body, and nothing else about the request.
4. **Caching.** `Cache-Control: public, max-age=86400, immutable` and a
   strong `ETag` derived from the body. A matching `If-None-Match` gets
   `304`. No `Last-Modified`; `Range` is ignored (the whole body is sent).
5. **Headers** on every `200`, `304` and `405` from these paths:
   - `Content-Security-Policy`: for `/connect`, `default-src 'none';
     script-src 'sha256-…'; style-src 'sha256-…'; img-src 'none';
     base-uri 'none'; form-action 'none'; frame-ancestors 'none'` — the page
     has exactly one inline `<style>` and one inline `<script>`, each allowed
     by its hash, and nothing else may load. For the other documents,
     `default-src 'none'; frame-ancestors 'none'; base-uri 'none';
     form-action 'none'; sandbox`.
   - `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
     `Referrer-Policy: no-referrer`.
   - `Permissions-Policy` denying every powerful feature (`camera=()`,
     `microphone=()`, `geolocation=()`, …). `clipboard-write` keeps its
     default (the page's own origin) for the copy button.
   - `Cross-Origin-Opener-Policy: same-origin`,
     `Cross-Origin-Resource-Policy: same-origin`.
   - `X-Robots-Tag: noindex, nofollow`.
   - `Strict-Transport-Security: max-age=31536000` when the relay's public
     base URL is `https`, whether the relay or a proxy in front of it
     terminates TLS. Browsers ignore it over plain HTTP.

**The `/connect` page.**

- One static page, the same for every relay running a given version of the
  relay software. It says to open the link in the VettID app and, without
  script, how: copy the whole address, including everything after the `#`,
  and paste it in the app.
- It MUST make no network requests: no subresources of any kind (scripts,
  styles, fonts, images — an inline SVG logo at most), no third-party
  content, no analytics. It suppresses the browser's default favicon fetch
  (`<link rel="icon" href="data:,">`). Links the reader may follow are
  allowed; they carry no referrer.
- It MUST NOT send the fragment anywhere. Its inline script MAY read the
  fragment locally only to build an "Open in VettID" link
  `vettid://connect#<link>` and a copy button that copies
  `<origin>/connect#<link>`. Before using the fragment it MUST check that it
  is base64url (`[A-Za-z0-9_-]`, bounded length), and it MUST NOT insert it
  as markup, store it (cookies, web storage) or navigate on its own.
- The page does not interpret the payload; the app does, and the payload,
  not the host, decides the relay (VAULT-MESSAGING §6.4).

**`/.well-known/assetlinks.json`.** A Digital Asset Links statement list
letting the VettID Android app handle the relay's links:

```json
[
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.vettid.app",
      "sha256_cert_fingerprints": ["31:A1:96:13:…:8E:65", "…"]
    }
  }
]
```

- Fingerprints are the SHA-256 of the app's signing certificates in
  uppercase, colon-separated hex.
- The relay software's **built-in default** names the official VettID app,
  so a self-hosted relay serves the official app's keys with no
  configuration. For this version the default is the production upload key
  `31:A1:96:13:AA:10:F2:09:E0:89:45:F9:47:F9:4F:7C:E3:E6:E5:AC:34:24:57:FF:99:69:A6:79:86:92:8E:65`
  and the two staging signers
  `BD:83:A0:75:3F:AA:6A:F6:F8:D8:1B:9F:76:A0:4A:C1:A4:99:EA:6C:7F:46:C6:F1:11:3D:4B:57:87:EC:B2:C4`
  and
  `2F:ED:27:B7:27:46:79:7A:93:1F:D4:14:FF:3D:AC:4C:D9:69:FA:0C:2F:F3:62:09:AE:05:36:5F:58:00:14:F2`
  (staging builds also use `relay.vettid.org`). The Play app-signing key
  will be added when it exists.
- Operators MAY replace the package name and the list (for example for a
  fork of the app). An empty list turns the document off: it gets the
  ordinary `404`.
- Android verifies an App Link only for hosts the app declares; the official
  app declares `relay.vettid.org`. On any other relay the document is
  harmless, and the page's `vettid:` link opens the app instead.

**Rate limits.** A relay SHOULD rate-limit these paths, and every other path
outside `/v1` except its health check, per client address (the IPv4 address
or the IPv6 /64), with a budget **separate** from the `/v1` limits (§7.2), so
that scanning can never use up the budget of mailbox traffic. The limiter
SHOULD be local to the relay process (no shared-store round trip), so
scanner bursts stay cheap. Over the limit: `429` `rate_limited` with
`retry_after` (§7.1, §7.2) and `Cache-Control: no-store`.

**Logging.** Nothing about these requests that could identify an invitation
or a visitor is logged. The fragment never reaches the relay; in addition, a
relay MUST NOT log the query string, the raw path of an unmatched request,
`Referer` or any other request header, or the client's address for these
paths. It MAY log the route (`/connect`, or a fixed word for unmatched
paths), status, sizes and duration. Operators SHOULD apply the same rules to
any proxy or load balancer in front of the relay.

**Configuration (informative).** The reference relay (vettid-relay) reads:

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_ANDROID_PACKAGE` | `com.vettid.app` | `package_name` in `assetlinks.json` |
| `RELAY_ANDROID_CERT_SHA256` | the official app's keys (above) | comma-separated fingerprints, colon form or plain hex in any case; set but empty turns `assetlinks.json` off |
| `RELAY_RATE_WEB_RPS` / `RELAY_RATE_WEB_BURST` | `2` / `20` | the per-address web bucket, per relay process |
| `RELAY_BASE_URL` | — | `https` turns on `Strict-Transport-Security` |

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
| `token_revoked` | 403 | `jti` or `sub` on the owner's denylist, or `iat` before a deleted mailbox's tokens-not-before (§6.10) |
| `mailbox_unknown` | 404 | no such mailbox — never registered, rotated away or deleted (§6.10) — or not yours (indistinguishable) |
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
backoff with jitter on `429` and `5xx`. The web endpoints (§6.11) are limited
with a separate budget.

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
9. **Deletion** (§6.10) is the owner's alone and erases content at once. The
   tombstone it leaves holds only the mailbox id and two times; it exists so
   that deleting a mailbox can never revive a token the owner revoked or a
   one-shot token already used. A stolen relay key can delete its mailbox —
   an availability event like any other use of a stolen owner key.
10. **Web endpoints** (§6.11) are public and unauthenticated by design. Their
    responses are constant, so probing them reveals only that a relay runs
    at the host, which its API reveals anyway; they hold no invitation
    state, so they are no oracle for invitations (claims stay behind
    `/v1/claim` and its own limits, §6.9). The invitation payload travels
    only in the URL fragment and never reaches the relay; the page's CSP
    forbids every request, so even a defect in its script could not send
    the fragment anywhere.

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

- **0.6.0** — web endpoints (§6.11): `/connect` (the invitation landing page
  of VAULT-MESSAGING §6.4), `/.well-known/assetlinks.json` (the VettID
  Android app's signing keys, configurable, the official app's by default),
  `/robots.txt`; `apple-app-site-association` reserved. Fixed responses
  (same bytes for every request, exact paths, `GET`/`HEAD` only, cacheable
  with a strong `ETag`), security headers, a per-address rate limit separate
  from the API's, and logging rules. Relays no longer redirect non-canonical
  paths; they get the ordinary `404` (§6.11). No `/v1` changes; additive for
  clients.

- **0.5.0** — owner-signed mailbox deletion, `DELETE /v1/mailbox` (§6.10):
  deletes the registration, messages, denylist, quota and open-token records,
  blobs and the claims it created, and predecessors still in their rotation
  grace; idempotent; parked collectors end with `mailbox_unknown`, WebSocket
  sessions close with 4404 (§6.3, §6.4). A re-registered key gets a fresh
  mailbox whose tokens must have `iat` at or after the deletion's
  tokens-not-before time (§5.3 step 6, `token_revoked`), kept as a tombstone
  for the maximum token lifetime. A rotated-away mailbox removed at the end
  of its grace leaves the same tombstone, timed from its removal (§5.5,
  §6.7), so re-registering an old key cannot revive its revoked or used
  tokens either. No new error codes. Additive for clients.

- **0.4.0** — collect results carry the deposit token's `jti` (§6.3, §6.4) so
  owners can distinguish a sender's tokens (VAULT-MESSAGING §6.6); `iat`
  backdating guidance raised to 60 s (§5.2). Additive for clients.
- **0.3.0** — first contact: one-shot open deposit tokens (§5.6; deposit
  only, no blobs) and single-fetch claims for bootstrap bundles (§6.9; TTL in
  the signed path, never retried by clients), with maximum lifetimes as advertised
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
