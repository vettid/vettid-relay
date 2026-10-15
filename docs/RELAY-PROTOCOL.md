# VettID Relay Protocol

**Version:** 0.9.0 (draft; the §7.2 resource limits are proposed and await approval)
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
| Message IDs | ULID (Crockford base32, 26 chars, upper case). Clients MUST send an id exactly as the relay issued it; a relay need not accept another spelling |
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
limit (`payload_too_large`, §8.5; on the declared length before anything
is read, and again while reading), then verify, in order (steps 1–6 need
only headers, and the relay SHOULD NOT read the body before them, §7.2):

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
It SHOULD NOT be able to use up the sender's rate limit either: the
per-sender limit applies after step 7 (§7.2).

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
- Keys are free to make, so a relay SHOULD limit the mailboxes one client
  network can create (§7.2). Registering an existing key again is not a
  creation and is not limited that way: clients MAY register at every
  start (VettID vaults do at every unlock).

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
- The relay assigns the ULID; per-mailbox ULID order is arrival order: a
  message deposited later never has a smaller id, whatever the relay's
  clock does. (vettid-relay: with the shared store this holds per mailbox
  across all processes; with the SQLite store it holds for the one process
  that may use a database file, and after a restart against the messages
  still stored.)
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

**The window (0.8.0).** A relay MAY bound the messages it has sent on a
session that are not yet acked there (§7.2: vettid-relay sends more while
fewer than 97 are outstanding, and up to 128 when whole batches are
waiting), sending more only as acks arrive or leases end; clients SHOULD
ack each message as soon as it is handled. An ack by
`DELETE /v1/mailbox/{msg_id}` (§6.5) deletes the message but does not make
room on the session before its lease ends. Order across redelivery is not
guaranteed.

Until the first lease of an unacked message ends, a session with a full
window is sent nothing more (a message deposited then arrives when those
leases end, up to one visibility timeout later). From then on vettid-relay
sends the unacked ones again in passes from the oldest to the newest the
session had been sent when the pass began: once per visibility timeout a
batch, taken before anything else when it is due, of at least 32 messages
and of 96 when nothing else is outstanding (which needs the previous batch
to have been written out in time: a slow reader gets a smaller batch,
never under 32). New messages are sent the rest of the time; they wait
only for a due batch's frames, unless the session itself has left more
than 64 unacked. An unacked message is thus sent again once in every pass.
A pass over n such messages is at most ⌈n/32⌉ batches, one visibility
timeout apart and never more than two: at most ⌈n/32⌉ visibility timeouts
for a session that acks the new messages it gets, 2⌈n/32⌉ in the worst
case, ⌈n/96⌉ for a session with nothing else outstanding, until the
message is acked or expires.

**Close codes (0.8.0).** A frame that is anything else, or whose `msg_id`
is not a ULID in upper case, ends the session with close code **1008** (a
frame larger than the relay reads, 1,024 bytes in vettid-relay, ends it
with **1009**). A session ended because an ack frame was refused by a rate
limit (§7.2) is closed with **1013** and reason `rate_limited`.

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
`retry_after` (§7.1, §7.2) and `Cache-Control: no-store`. The health check
is outside every limit, so what a request to it costs is bounded another
way: a relay SHOULD answer it (`/healthz` in vettid-relay) from a store
check no older than a few seconds (vettid-relay: 2 s).

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

The rest of this section (0.7.0) says how a relay SHOULD limit, and gives
the reference relay's numbers. None of it is visible to a client except as
fewer or more `429`s (to WebSocket upgrades too, under limits 7 to 9, and
to deposits, claims and blob transfers under limits 11 to 13), as a blob
transfer dropped when its body stalls (13) and, on a WebSocket session,
as close code 1013 `rate_limited` when an ack frame is refused by a rate
limit (§6.4).

**Principle.** A client's address is the right key for a limit only while
the caller is unauthenticated. Addresses are shared: every vault on a vault
host reaches the relay from that host's one address (hundreds of vaults),
and phones behind a carrier NAT share theirs. So once a request is
attributed to a key, the relay limits the **key**. "Network" below means
the IPv4 address or the IPv6 /64. (Whoever holds a larger IPv6 prefix holds
many networks, a /48 65,536 of them: every per-network limit below then
binds per /64 only, and what bounds such a holder is what is not keyed on
a network: the per-process and per-key limits.)

**The limits.**

| | Limit | Key | vettid-relay default | Applies |
|---|---|---|---|---|
| 1 | flood guard | network | 100/s, burst 300 | to every `/v1` request, first, before anything is parsed |
| 2 | per key | signing key | 20/s, burst 100 | once the request is authenticated: on owner routes after the signature verified, was no replay, and the signer's mailbox exists; on registration and mailbox deletion after the signature verified; and to every ack frame of a WebSocket session (§6.4) that does not name a message sent on that session and still leased to it (a message received elsewhere, an id acked before, an ack after the lease ended, an id that names nothing): such a frame draws on the flood guard (1) and on this limit like the `DELETE /v1/mailbox/{msg_id}` it stands for, and the session is closed with 1013 `rate_limited` when either is empty. An ack frame is uncharged once for each message in the window: a duplicate ack is charged, and so is a duplicate ack after a lease ended |
| 3 | new mailboxes | network | 1/s, burst 30 | to a registration that creates a mailbox, and to a rotation (§6.7). Registering an existing key again draws nothing (clients do that routinely, §6.1) |
| 4 | per sender | token `sub` (an open token's `jti`, §5.6) | 5/s, burst 20 | to deposits and blob uploads, after §5.3 step 7 (the token's `sub` is written by the mailbox owner; only the signature proves the sender) |
| 5 | claim fetches | network | 1/s, burst 10 | to `GET /v1/claim/{id}` (§6.9), the one unauthenticated operation |
| 6 | collectors | mailbox | 4 | to parked long-polls and WebSocket sessions together |
| 7 | WebSocket sessions | relay process | 4,000 | to upgrades of `GET /v1/mailbox/ws`; beyond it `429` with `retry_after` 5. Long-poll is not affected |
| 8 | WebSocket sessions per network | network, per relay process | 1,024 | to an upgrade for a mailbox that already has a WebSocket session on that process; the first session of a mailbox is admitted beyond it, up to 9. `429` with `retry_after` 5 |
| 9 | WebSocket sessions per network, ceiling | network, per relay process | 2,000 | to every upgrade, a mailbox's first session included: no network holds more on a process. `429` with `retry_after` 5. At least 8 and at most 7 |
| 10 | WebSocket window | session | 128 messages | to messages sent on a session and not yet acked there: the relay leases a further batch (32) only while it fits, so it pauses at 97 or more outstanding, until acks arrive or leases end |
| 11 | stored bytes | network, per relay process | 256 KiB/s, burst 8 MiB | charged in bytes: to deposits after §5.3 step 6, with the declared body length (without a `Content-Length`, the largest deposit body), **before the body is read** (a refused deposit is not read); to claim creation (§6.9) once its signature verified and the signer's mailbox exists, with the claim's length. A deposit or claim that is then not stored (quota, signature, malformed body, store failure) is refunded. `429` with `retry_after` |
| 12 | blob bytes | authenticated key, and network as a ceiling; per relay process | per key 1 MiB/s, burst 32 MiB; per network 8 MiB/s, burst 256 MiB | charged in bytes. Blob uploads: the key is the token's `sub`, which the mailbox owner wrote and the request signature proves only after the body (§5.3 step 7); so after §5.3 steps 1–6 and before the body is read, the network's ceiling is charged with the declared length (without one, the largest blob) and the key's budget is only checked (an empty one is refused unread); once the signature has verified the key's budget is charged with the bytes received, unconditionally (it may go into debt). Blob downloads: after the owner's signature verified, the owner's key and the network's ceiling are charged together with the blob's size, at most a key's burst (refused by either, charged to neither). An upload that stores nothing is refunded only the part of its network charge it never sent: the bytes that reached the relay stay charged whatever refused it (body failure, signature, quota, store failure); an upload refused a transfer slot (13), which held none, is refunded entirely. A download by an owner whose budget, or whose network's, is empty is refused before the store is read. `429` with `retry_after` |
| 13 | blob transfers | relay process; mailbox; sender and mailbox | 8 per process; per mailbox 2 uploads and, apart, 2 downloads; 1 upload per sender key and mailbox; uploads at most 8 − 2 = 6 per process | to blob uploads once their body has begun to arrive (an upload that has sent nothing holds no slot), and to blob downloads; the mailbox is the recipient's for an upload and the owner's for a download. Uploads never take a mailbox's download slots nor the 2 process slots kept for downloads. `429` with `retry_after` 2. A transfer's body must move at least 16 KiB in every 5 s and finish within 5 minutes, or the transfer is dropped (an upload is answered `400` with `Connection: close`): an upload that trickles at the minimum pace holds its slot up to 5 minutes |

Nothing else is keyed on a network. A request that is properly signed by a
key with a mailbox can be refused on account of its network only by the
flood guard (1), by the byte budgets for what it would store or move (11,
and 12's ceiling) and, if it would create a mailbox, by the new-mailbox budget (3): no
client is refused for what another client behind its address did, beyond
those. There is no penalty state: a relay that
refuses a network does so only for as long as its bucket is empty.

**Order of checks.** The flood guard comes before everything a request
can cost: every signature verification, replay record (§4.1) and store
read happens after it, so the guard bounds them all. Then, per request:
the body size limit; for deposits and blob uploads the header-only steps
of §5.3 (1–6) **before the body is read**, then for deposits the byte
budget (11) and for blob uploads the blob byte budget's network ceiling
(12, with a look at the key's), still before the body is read; the
signature; then for deposits and blob uploads the per-sender limit (4),
and for blob uploads the key's blob budget (12); on owner
routes the mailbox lookup **before** the replay check, so that a key
without a mailbox writes no replay record (a deposit's mailbox was looked
up in step 1); the per-key or per-sender limit; for claims the byte
budget (11), for blob downloads an empty blob budget (12) refuses before
the store is read, then the transfer slot (13), the store read and the
charge with the blob's size; for blob uploads the transfer slot (13) once
the body begins to arrive. A charge for a request that ends up storing
nothing is refunded as limits 11 and 12 say. A request that
is refused before its body has been read SHOULD be answered at once with
`Connection: close`, not after waiting for the body. A small body that
has to be read before the request can be authenticated (registration,
rotation, denylist, claim: at most 16 KiB) SHOULD have a short deadline
(10 s in the reference relay: 13 kbit/s is the slowest link served for
these requests), after which the request is refused and the connection
closed.

**No oracles.** A limit MUST NOT answer differently depending on whether a
mailbox, key, token or claim exists, except to the holder of the key
concerned. The network limits never look at a request's target (the
new-mailbox budget is consulted only for the holder of the key being
registered; the byte budgets are charged for a deposit only after its
mailbox is known to exist, which a deposit's answer says to anyone, and
for a claim or a blob download only to the key's holder). The key and sender limits apply only after the caller has
proved the key is its own.

**`retry_after`** is the whole seconds until one request is allowed, at
least 1 (for a byte budget: the whole seconds until the request's bytes
are there). A mailbox at its collector maximum gets 1; a process or a
mailbox without a free blob transfer slot (13) gets 2; a relay process at
its maximum of WebSocket sessions (7), a network at its maximum (8) or at
its ceiling (9), and a relay that cannot reach its replay store answer
with 5.

**Where the numbers come from (informative).** One unlocked vault, read
from vettid-vault (`vault/relay.go`, `vault/inbound.go`, relayclient),
makes one long-poll collect every 25 s while idle (0.04 requests a
second); per message received, one ack and the next collect; per message
sent, one deposit; at unlock, one registration of its existing key, a
collect and about one deposit per device. The Android app's collector
does the same on its own mailbox.

- *Flood guard, 100/s.* Deliberately conservative for the first
  deployment: five times the old single bucket (20/s, burst 40), enough
  for the hosts expected in the coming months, and to be raised from
  measurement. A host's steady traffic reaches 100/s at about **2,500 idle
  vaults**, about **1,100 vaults** that each receive and send a message a
  minute, or about **700** at two messages a minute. A host of 900 vaults
  (the projected size) is 36/s idle and about 81/s at a message a minute
  each.
- *Burst 300.* Steady traffic needs the rate; the burst is what a single
  instant may bring, and also what makes every memory cost below
  instantaneous, so it is kept small. About **100 vaults can unlock in the
  same instant** (three requests each); the next are answered `429` with
  `retry_after` 1 and get through a second later (the vault's relay client
  waits and retries). When a relay deploy ends every long-poll of a host
  together, up to 300 vaults re-poll without a refusal; of 500, 276
  requests are refused once and all are polling again after 2.5 s; of 900,
  about 1,800 refusals over 7 s; in neither case do refusals recur
  (simulated, with the client's retries; the same with and without the 20
  to 25 s poll jitter of newer vaults).
- *Per key, 20/s, burst 100.* 500 times an idle vault; a message costs its
  recipient two requests, so 10 messages a second sustained; the burst is
  three full batches of 32 with their acks.
- *Stored bytes, 256 KiB/s, burst 8 MiB.* The per-mailbox and per-key
  caps do not bound a network: mailboxes and keys cost nothing. At the
  flood guard alone one address could store about 26 MB a second (100
  deposits of 262,144 bytes). A host of 900 vaults at a message a minute
  each of 4 KB stores about 15 a second, about 80 KB/s of deposit bodies
  (base64 makes 4 KB about 5.5 KB): about a third of the budget; the burst
  holds about 1,500 such deposits at once. A mass unlock is paced by the
  flood guard first (a third of its requests are deposits, about 180 KB/s).
  The budget is charged with the declared body length (base64 included),
  so a deposit refused later (quota, signature) has still been charged.
- *Blob bytes, per key 1 MiB/s, burst 32 MiB; per network 8 MiB/s, burst
  256 MiB.* Attachments go phone → own vault → peer vault → peer phone,
  so they pass through vaults, and a vault host carries hundreds of vaults
  behind one address: a single budget per network would throttle the
  whole host as one. So the budget is per authenticated key, the vault's
  (or phone's) own, and the network has a ceiling above it. A vault
  forwards each attachment twice (it downloads it from its mailbox and
  uploads it onward), so a key's burst of 32 MiB is two maximum-size
  attachments through a vault at once, or four blobs from a phone; 1 MiB/s
  sustained is far above any one member. A host of 900 members each
  sending five 1 MB attachments a day, each crossing the host 2 to 4
  times, moves about 0.2 MB/s on average; a peak hour at ten times that
  is a quarter of the 8 MiB/s ceiling, and the 256 MiB burst holds 32
  maximum-size attachments crossing at once. Memory is bounded by the
  transfer slots (13), not by the budget: 8 transfers of 8 MiB, 64 MiB a
  process. 8 MiB/s (67 Mbit/s) is about what one small relay task can
  move, and bounds a network's blob egress at about 0.7 TB a day per
  process (an estimate: about $65 a day at $0.09/GB).
- *Blob transfers, 8 per process; per mailbox 2 uploads and 2 downloads;
  one upload per sender and mailbox; 16 KiB per 5 s.* A blob is held in
  memory while it moves, so transfers are bounded. Uploads and downloads
  are counted apart so that senders cannot keep an owner from its blobs,
  and one sender cannot take both of a mailbox's upload slots. The slot
  is taken only once an upload's body arrives and is dropped when the
  body stops moving, so a client that announces uploads and stalls holds
  no slot, and one that stalls part-way holds it for 5 s; one that keeps
  the minimum pace holds it up to the 5-minute maximum.
- *Refunds.* The byte budgets bound what is stored, so a deposit or
  claim that stores nothing is given its charge back: a vault host's
  sender retrying against a full mailbox does not drain its host's budget.
  A blob upload that held a transfer slot keeps charged every byte it
  sent, whatever then refuses it, so holding an upload slot always costs
  the bytes trickled while holding it.
- *New mailboxes, 1/s, burst 30.* Members enrolling on one host or behind
  one NAT are a few an hour; 30 covers a batch (a test run, a small
  migration). The burst matters only for the first seconds: the rate is
  what bounds how many mailboxes one address can accumulate (86,400 a
  day). A host unlocking many vaults at once does not draw on it:
  re-registration is free.

**What this fixes.** A host's vaults no longer share 20 requests a second:
each key has its own budget, and the host as a whole 100/s. No client is
refused because of another client behind its address, except by the flood
guard and the new-mailbox budget. A leaked deposit token cannot use up its
sender's budget, and an unauthorized deposit's body is not read.

**What does not hold (this version is the core; see "Later").**

- **One address can make the relay do five times what it could before:**
  100 signature checks, replay records and store reads a second (20
  before), and a burst of 300 (40 before). Requests that fail are not
  refused any more cheaply than requests that succeed: garbage from an
  address costs a signature check each, a properly signed request under a
  fresh key a replay record and a store read each, up to the guard.
- **A client whose mailbox is gone and that keeps asking** (a vault retries
  a collect answered `mailbox_unknown` every second) costs a signature
  check, a replay record and a store read per retry, and one request a
  second of its host's flood guard: 1% of it per such vault, where a
  900-vault host idle uses 36%.
- **Parked collectors are bounded only per mailbox** (4, per relay
  process) and by what the flood guard and the new-mailbox budget let one
  address build up. Long polls have to be re-issued every 25 s, so one
  address can keep about 2,500 parked (100/s × 25 s; 500 before), plus the
  burst: at a measured 42 KiB each, about 105 to 120 MiB across the
  relay's processes. WebSocket sessions cost one request each and do not
  end. A network can hold 1,024 **on each relay process** (8) after about
  4 minutes, and beyond that one per mailbox it registered up to 2,000 (9;
  about 88 MiB at a measured 45 KiB) after about 20 minutes, and no more:
  one network cannot fill a process (7: 4,000), two can. The counts are
  per process, so a network can hold 2,000 on each process; and per
  network, so the holder of a larger IPv6 prefix is bounded by 7 only. A
  vault host with more than 2,000 vaults behind one address on one process
  exceeds 9: its further vaults are refused the upgrade and must collect
  by long-poll, or the operator raises it. (Clients SHOULD fall back to
  long-poll on a `429` upgrade; a client that only retries the WebSocket
  stays without a collector.) A session that does not ack costs, with no
  request, up to its window (10) in leases per visibility timeout and as
  many uncharged ack frames: about 2 of each a second per session, about
  4,300 a second for the 2,000 sessions of one network on a process.
- **A deposit's body can still be made to stall.** It is read after the
  deposit token verified but before the request signature and the
  per-sender limit, and it has no deadline of its own. Anyone with one
  registered mailbox can mint tokens of its own for fresh sender keys and
  send deposits to itself whose bodies stop one byte short: each holds
  its buffer (up to about 380 KiB) until the server's or the load
  balancer's timeout, refused by no limiter but the flood guard. In the
  review that was 112 MiB for 300 such deposits from one address, which
  is the burst: about 110 MiB at once, then 38 MiB a second. Before this
  version the same needed no credential at all and reached about 580 MiB
  inside the load balancer's 75 s (40 at once, then 20 a second). The
  remedy is the body pace under "Later".
- **Small bodies that are announced and then stall** (registration,
  rotation, denylist, claim) are read before the signature can be
  checked; with the 10 s deadline one address can hold about 1,300 such
  connections (100/s × 10 s, plus the burst).
- **The new-mailbox budget is per address** (1/s): anyone behind an
  address can use it up, and other enrolments and rotations from that
  address then wait their turn.
- **Storage and its cost are bounded per network by limits 11 and 12, and
  relay-wide only by the deployment** (the store's throughput ceiling, the
  blob bucket's expiry). The byte budgets are per process: behind N relay
  processes a network can store up to N times 256 KiB/s. Many addresses
  together can still fill the relay up to the deployment's ceiling. Per
  mailbox, vettid-relay keeps at most 10,000 messages and 32 MiB of them
  (and 64 MiB of blobs and claims); a mailbox above a lowered cap keeps
  what it holds and takes no deposit until it is under the cap again.
  Expired messages are never delivered but may stay stored for a few days
  until the store's expiry removes them.
- **Mailboxes never expire.** One address can create 86,400 a day (3);
  each is small, but their number only grows (see "Later").
- **Upload slots are shared by all networks on a process.** One address
  with three mailboxes of its own and two sender keys for each (it mints
  its own tokens) can hold the 6 upload slots of a process by keeping each
  upload at the minimum pace for up to 5 minutes. That costs it the bytes
  it sends, about 960 KiB per slot per round (16 KiB every 5 s), some 6
  MiB per round of all 6, well inside its blob budgets: other senders'
  uploads on that process are answered `429` until a slot frees. Uploads
  alone cannot keep owners from their blobs: 2 process slots and each
  mailbox's download slots are never given to uploads.
- **Download slots are shared by all networks on a process too.** An
  address with its own mailboxes and blobs can download them slowly at the
  minimum pace and hold all 8 slots of a process, each for up to 5
  minutes (a blob of about 960 KiB lasts that long at the pace), at the
  cost of each blob's size from its blob budgets (12): about 8 MiB per
  round of 8, well inside them. Other owners' downloads on that process are
  then answered `429` until a slot frees.
- **Blob keys cost nothing.** Anyone with a mailbox mints tokens for
  fresh sender keys, each with its own blob budget (12), so what bounds
  one network's blob traffic is the network's ceiling, 8 MiB/s per
  process, not the key's budget; a vault host's honest traffic shares
  that ceiling with anything else behind its address. The reverse does
  not hold: a token whose `sub` names another's key (anyone can mint one
  for their own mailbox) cannot spend that key's budget, which is charged
  only once the request signature has proved the key.
- **The deposit byte budget (11) is per network.** Messages pass through
  vaults the same way attachments do, so a vault host's vaults share it:
  about a third of it at a message a minute per vault for 900 vaults, all
  of it at about three.
- **Many addresses at once:** no per-network limit helps; that is the load
  balancer's, the scaling policy's and, if ever needed, a web ACL's job.

**Later (designed and reviewed, not in this version).** Each returns when
the measurement named says it is needed; the relay reports all of them
(Observability).

| Mechanism | What it adds | Measurement that justifies it |
|---|---|---|
| a higher flood guard (rate and burst: 200/s, burst 4,000 was reviewed for hosts of 1,000 to 2,000 vaults) | larger hosts | rate: the busiest address at half the guard for minutes (3,000 requests a minute). Burst: refusals of a known host after relay deploys or mass unlocks |
| caps on parked long-polls per network and process (WebSocket sessions have theirs: 7, 8, 9); session counts shared between processes; a maximum lifetime for WebSocket sessions | bounded memory for parked connections | collectors per process against its memory; refusals under 8 and 9; sessions per process |
| body memory counted as it arrives, a pace for bodies (deposits included), separate pools | bounded memory and time for stalled bodies: the follow-up for the deposit case above | connections held open in body reads; process memory under stalled requests |
| a per-network budget of failed authentications, with signature-first handling for a network that used it up | garbage refused cheaply | refusals and error rates by code from single addresses |
| holding a key that signs properly but has no mailbox, with a growing `retry_after` | an orphaned client stops costing a store read per retry | `mailbox_unknown` answers per minute |
| refused-deposit budgets per sender and per (sender, mailbox) | a sender spraying refused deposits | refused deposits by code |
| byte budgets shared between processes | a network's byte budget the same however its requests are spread | `bytes_busiest_per_min` near the budget on several processes at once |
| expiry of a mailbox not collected from for 400 days (the longest reconnect-token lifetime) | the number of mailboxes stops only growing | mailbox count against active collectors |

**No allowlist.** The relay does not exempt known addresses (vault hosts).
An allowlist would be a second configuration to keep right as hosts come
and go, and would give whoever gains use of a listed address an unlimited
relay.

**Shared state.** With several relay processes, limits 1 to 5 are shared
(their observable budget is the same however requests are spread); limits
6 to 9 and 11 to 13 are per process (a client that reconnects to another
process is counted there afresh), and 10, with the order of re-sends, is
each session's own. If the shared store cannot be reached, the shared limits
fall back to per-process buckets (limits are best-effort policy;
availability matters more), while signed requests are shed with `429` as
long as replays cannot be recorded (§4.1).

**Observability.** A relay SHOULD report, with no dimension that
identifies a client (no address, key or mailbox): per limit, the requests
allowed and refused and how full its busiest bucket got; the number of
requests made by the busiest single network and the busiest single key;
the number of networks the flood guard refused; and the parked collectors
and WebSocket sessions it carries. These are what the limits above are to
be re-sized from. vettid-relay exports `relay_ratelimit_allowed_total`,
`relay_ratelimit_refused_total`, `relay_ratelimit_peak_permille` (by
limiter: `address`, `key`, `sender`, `register`, `claim`, `web`;
`relay_ratelimit_refused_total` also has `ws_sessions`, `ws_network` and
`ws_network_hard`, the upgrades refused under 7, 8 and 9, which the
`rate limits` line ends with as `ws_sessions_refused`,
`ws_network_refused` and `ws_network_hard_refused`; and, added in 0.9.0,
the byte budgets `bytes` (11) and `blob_bytes` (12, the network's
ceiling) and `blob_key_bytes` (12, per key), and the blob
transfers refused under 13, `blob_slots` (the process) and
`blob_mailbox_slots` (the mailbox) and `blob_sender_slots` (the sender's
upload to that mailbox)),
`relay_ratelimit_busiest_per_minute` (`address`, `key`),
`relay_ratelimit_busiest_bytes_per_minute` (`bytes`, `blob_bytes`,
`blob_key_bytes`: the bytes charged to the busiest single network or
key),
`relay_active_collectors`, `relay_parked_collectors` and
`relay_ws_sessions`, and logs all of it once a minute in one `rate limits`
line, which after the WebSocket refusals ends with `bytes_peak`,
`bytes_refused`, `bytes_busiest_per_min`, `blob_bytes_peak`,
`blob_bytes_refused`, `blob_bytes_busiest_per_min`, `blob_key_bytes_peak`,
`blob_key_bytes_refused`, `blob_key_bytes_busiest_per_min`,
`blob_slots_refused`,
`blob_mailbox_slots_refused`, `blob_sender_slots_refused`, `log_dropped`
and `log_suppressed`. A relay SHOULD bound its own log volume without
losing what an operator relies on: vettid-relay writes at most 100 info
lines a second per process (burst 1,000; the rest are counted in
`log_dropped`); the request lines of successful registrations, rotations, denylist
changes and mailbox deletions draw on a second budget of the same size, which other
lines cannot use up; it logs refusals (`429`) at debug; it writes one warn
or error message with the same error, route and panic at most once per
10 s (the rest counted in `log_suppressed`); and it never drops the `rate
limits` line (a deployment can alarm when it goes missing) or its own
start, drain and stop lines.

**Configuration (informative).** vettid-relay reads, each as `_RPS` and
`_BURST`: `RELAY_RATE_IP` (1), `RELAY_RATE_KEY` (2),
`RELAY_RATE_REGISTER` (3), `RELAY_RATE_SENDER` (4),
`RELAY_RATE_CLAIM_GET` (5), `RELAY_RATE_WEB` (§6.11); and
`RELAY_MAX_COLLECTORS_PER_MAILBOX` (6), `RELAY_MAX_WS_SESSIONS` (7),
`RELAY_MAX_WS_SESSIONS_PER_NETWORK` (8) and
`RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD` (9), with 8 ≤ 9 ≤ 7 (the relay
refuses to start otherwise). The window (10) is not configurable.
`RELAY_RATE_IP_BYTES` (11), `RELAY_RATE_BLOB_KEY_BYTES` and
`RELAY_RATE_BLOB_BYTES` (12: per key, and the network's ceiling), each as
`_PER_SEC` and `_BURST`, in bytes; `RELAY_MAX_CONCURRENT_BLOB_TRANSFERS`
and `RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX` (13), and
`RELAY_BLOB_PACE_BYTES` (per 5 s); `RELAY_MAILBOX_MAX_BYTES` (32 MiB);
`RELAY_LOG_INFO_RPS` and `RELAY_LOG_INFO_BURST`. The relay refuses to
start unless the burst of 11 holds the largest deposit body and the
largest claim, the mailbox cap holds at least one message and, with blobs
enabled, a key's burst under 12 holds the largest blob, the network's
ceiling is at least a key's rate and burst, and the per-mailbox
transfers are fewer than the process's. Every rate, every burst and the
blob pace must be greater than zero, whether blobs are enabled or not.

**Clients.** Nothing changes on the wire, except for WebSocket sessions
(0.8.0): an upgrade can be answered `429` under limits 7 to 9, and a
session can be closed with 1013 `rate_limited` when an ack frame is refused
by a rate limit (§6.4). Clients SHOULD retry a `429` no
sooner than `retry_after`, with their own jitter (a deposit, claim or blob
transfer answered `429` under 11 to 13 is retried like any other; deposits
and blob uploads SHOULD carry a `Content-Length`, since without one they
are charged the largest body; an upload SHOULD send its body without
pauses, since one that stops moving is dropped with `400`); SHOULD treat
`mailbox_unknown` on their **own** mailbox as final until they have
registered again (stop collecting, register, resume; or stop, if the
mailbox was deleted on purpose) instead of asking again every second; and
SHOULD treat `timestamp_stale` as a wrong local clock and back off. A
client whose WebSocket upgrade is answered `429` SHOULD collect by
long-poll and try the WebSocket again no sooner than `retry_after`, with
backoff; a client whose session is closed with 1013 SHOULD back off before
reconnecting.

### 7.3 Versioning

The URL prefix (`/v1`) is the major version. Backward-compatible additions
(new optional fields, new endpoints) bump the spec's minor version without a
prefix change. This document carries a semver and a changelog (§10).

### 7.4 The HTTP/2 front end (deployment, 0.7.1)

A relay that serves HTTP/2, itself or through a load balancer, announces
how many requests a client may have open on one connection
(`SETTINGS_MAX_CONCURRENT_STREAMS`, RFC 9113 §6.5.2). For most clients
the number does not matter. For a vault host it does: every vault on the
host holds one long-poll (§6.3) on connections they all share, and the
host's enclave decides how many connections to open from the limit the
relay announces (VAULT-MESSAGING §12.2.1).

- A relay's front end **MUST NOT announce exactly 100** concurrent
  streams. 100 is what the vault's HTTP/2 library (Go's) assumes before
  a host has announced anything, and the library does not say when the
  announcement arrived. A connection that reads 100 is therefore
  trusted only once it has answered a request: until then it carries 1
  request, after a second fewer than 32, and when its first requests
  are all long-polls that can last up to 25 s, during which the host's
  other vaults wait (VAULT-MESSAGING §12.2.1; VAULT-RELAY-SCALING
  §10.4).
- It **SHOULD announce at least 128**. Below **32** a vault host opens
  no second connection at all, so that a relay cannot split the vaults
  of a host over many connections and tell them apart: every request
  beyond the limit then waits for a stream.
- HTTP/2 already requires PING frames to be answered (RFC 9113 §6.7). A
  vault host depends on it: it pings a connection after 15 s without a
  frame and closes it when no answer comes within 10 s.

These are requirements on a deployment, not on the wire format, and
nothing in `/v1` changes. relay.vettid.org is behind an AWS Application
Load Balancer, which announces 128 and answers pings; the value is not
configurable there (read from its `SETTINGS` frame on 2026-10-12).
Anyone who puts another front end before a relay that vault hosts use
(another load balancer, a CDN, a reverse proxy) checks the number it
announces first. Some servers and proxies default to exactly 100.

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
   the per-network flood guard (§7.2) SHOULD apply before token parsing;
   signature verification (cheap for Ed25519) precedes any database write.
   A client's address is a limit's key only while the caller is
   unauthenticated; authenticated callers are limited per key (§7.2), so
   that many clients behind one address (a vault host, a carrier NAT) are
   not one bucket. §7.2 "What does not hold" lists what one address can
   still cost the relay.
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
  background service in lieu of the gateway. VettID's app makes that
  on-phone service the default and offers FCM via the gateway as an
  option (ANDROID-PLAN D7, owner decision 2026-10-09).

The push gateway API is specified separately.

## 10. Changelog

- **0.9.0 (proposed)** — resource limits, as built in vettid-relay (§7.2,
  no wire change). Byte budgets: what a network asks the
  relay to store (deposits, claims: 11, 256 KiB/s, burst 8 MiB) and its
  blob traffic (uploads and downloads: 12, per authenticated key 1 MiB/s,
  burst 32 MiB, under a network ceiling of 8 MiB/s, burst 256 MiB),
  charged with the declared length before the body is read, `429` with
  `retry_after`, refunded when nothing is stored. Blob transfers (13): 8
  per process, uploads and downloads counted apart per mailbox (2 each),
  one upload per sender and mailbox, 2 process slots kept for downloads,
  a slot held only while the body moves, a pace of 16 KiB per 5 s and at
  most 5 minutes per transfer. The per-sender limit (4) applies to blob
  uploads after the signature, as to deposits. Owner routes look the mailbox up before writing
  the replay record. The reference relay's mailbox cap goes from 128 MiB
  to 32 MiB; it bounds its log volume. New counters, `rate limits` fields
  and configuration variables; nothing removed or renamed.
- **0.8.0** — WebSocket sessions are bounded, as built in vettid-relay #9;
  approved by the owner 2026-10-13. Until now the limits of §7.2 applied
  to a session's upgrade request only. Now (§6.4, §7.2): a relay process
  carries a maximum of sessions (7: 4,000 in the reference relay), and of
  one network a maximum (8: 1,024) beyond which only the first session of
  a mailbox is admitted, up to a ceiling (9: 2,000); a refused upgrade is
  `429` with `retry_after` 5 and long-poll is not affected. A session has
  a window of messages sent and not yet acked (10: 128); a session that
  lets leases end is sent the unacked messages again in rationed batches,
  one per visibility timeout, with new messages in between. An ack frame
  that does not answer a message in the window is charged to the flood
  guard and the key's limit like the `DELETE` it stands for. Close codes:
  **1008** for a frame that is not an ack of a well-formed id, **1013**
  with reason `rate_limited` when a charged ack is refused. Message ids
  are upper case and clients MUST send them as issued (§2); ULID order
  holds whatever the relay's clock does (§6.2). The health check answers
  from a store check a few seconds old at most (§6.11). New refusal
  counts and three configuration variables (§7.2). For clients: fall back
  to long-poll on a `429` upgrade, back off after 1013; no new endpoint,
  field or error code.
- **0.7.1** — a deployment requirement, no wire change (§7.4, new): a
  relay's HTTP/2 front end MUST NOT announce exactly 100 concurrent
  streams and SHOULD announce at least 128 (and vault hosts rely on
  its answers to PING frames).
  The requirement was already made of VettID's relay in
  VAULT-MESSAGING 0.27.2 §12.2.1 and VAULT-RELAY-SCALING §10.4; it is
  stated here because it binds whoever deploys a relay. relay.vettid.org
  announces 128.
- **0.7.0** — rate limiting by key (§7.2, rewritten; §8 item 5). The
  single per-address bucket in front of `/v1` (20 requests a second in the
  reference relay) counted every client behind an address as one: about 500
  idle vaults on one vault host used all of it. Now: a per-network flood
  guard (100/s, burst 300 in the reference relay), first, bounding every
  signature check, replay record and store read; a per-key limit once a
  request is authenticated, and no network-keyed limit after that except
  a budget of new mailboxes (re-registration is free, §6.1); the
  per-sender limit moves after the deposit's signature check, and a
  deposit's body is read only after its token verified (§5.3); limits are
  no oracle; what a relay should measure; what this version does not
  protect against, and the mechanisms left for later. Behaviour a client
  may notice against 0.6: the per-sender limit on deposits now follows
  the body, the signature and the replay record, so a sender over its
  limit signs its retry afresh (clients do); small bodies have 10 s to
  arrive; refused requests with an unread body close the connection. No allowlist of
  vault hosts. **Nothing changes on the wire**: no new endpoint, field or
  error code; clients need no change and see fewer `429`s.

- **0.6.1** — Appendix A: the on-phone background service is VettID's
  default; FCM via the gateway is an option (ANDROID-PLAN D7, owner
  decision 2026-10-09). Informative only.

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
