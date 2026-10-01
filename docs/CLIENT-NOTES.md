# Relay client notes

These notes are for people implementing relay clients: the vault
(vault-manager in the enclave, plus the parent-instance forwarder), apps
(Android, iOS, desktop) and agents. The normative text is
[RELAY-PROTOCOL.md](RELAY-PROTOCOL.md). `internal/client` in this repository
is a compact reference implementation in Go.

## 1. Keys and addresses

- Generate a **dedicated** Ed25519 relay keypair. It must not be the protean
  credential key or an E2E messaging key. Vaults keep it inside the enclave
  (sealed vault state). Apps keep it in the platform keystore.
- `mailbox_id = lowercase(base32(SHA-256(pubkey)))`, with padding removed,
  truncated to 26 characters. Check your implementation against the §9.1
  vectors.
- An address is `mailbox_id@relay_base_url`. Exchange addresses inside
  E2E-encrypted channels, never through the relay.

## 2. Signing every request

```
canonical = METHOD "\n" PATH "\n" TIMESTAMP "\n" hex(SHA-256(body))
X-VettID-Sig = base64(Ed25519(key, SHA-256(canonical)))
```

- **PATH** is the URL path exactly as sent, including `/v1`, without the
  query string. **body** is the exact bytes on the wire: an empty string
  for GET or DELETE, and the raw ciphertext for blob PUT.
- Base64 is standard **with padding** (`+/`, `=`) for keys and signatures.
- **TIMESTAMP** is RFC 3339 UTC. **Use fractional seconds**, for example
  `2026-06-10T12:00:00.123Z`. The query string isn't signed and Ed25519 is
  deterministic, so two identical requests in the same second, such as a
  long-poll re-issued right after a response, would carry the same
  signature. The relay would reject the second as `replay_detected`.
- Keep the clock in sync. The relay rejects timestamps more than 90 s off
  (`timestamp_stale`). If you get `timestamp_stale` repeatedly, fix the
  clock rather than retrying.
- Never reuse a signed request. Each retry gets a new timestamp and a new
  signature.
- Check your implementation against the §9.3 vector before talking to a
  relay.

## 3. Deposit tokens (the recipient mints them)

- A deposit token is a PASETO **v4.public** token signed with the
  recipient's relay key. Its claims are compact JSON in the order `iss`,
  `sub`, `aud`, `iat`, `exp`, `jti`, `scope`, optionally followed by
  `quota`.
- `iss` is the recipient's mailbox id.
- `sub` is the sender's base64 relay pubkey (canonical padded base64).
- `aud` is the relay base URL, matched **exactly** with no trailing slash.
- `scope` is `"deposit"`.
- There's no footer and no implicit assertion. Your signer must reproduce
  the §9.2 token byte-for-byte.
- **Lifetimes.** Standing (connection) tokens last at most 30 days, and
  one-shot tokens at most 5 minutes. This relay rejects tokens with
  `exp − iat` above its configured maximum (default 30 d).
- **Clock skew.** The relay checks `iat ≤ now < exp` strictly. Backdate
  `iat` by a minute so a recipient clock that runs ahead doesn't make fresh
  tokens `token_expired`.
- **`jti`** is unique per token. A ULID is recommended, and it's the
  revocation handle.
- **Vault side.**
  - Approving a connection mints a token for the counterparty and delivers
    it over E2E.
  - Revoking a connection posts `{"kind":"sub","value":<their pubkey>}` to
    the denylist (or `{"kind":"jti", …}` for one token).
  - Re-mint before expiry.
- **Sender side.**
  - Cache tokens per (recipient, relay) and refresh them before `exp`. For
    an app, refresh means asking its vault over OwnerSpace.
  - On `token_expired`, refresh the token. On `token_revoked`, stop and
    surface the error. A leaked token is useless without your private key.

## 4. Receiving: collect, dedupe, ack

- Delivery is **at-least-once**. Messages not acked within
  `visibility_timeout_seconds` (default 60 s) come back.
- **Deduplicate by `msg_id`.** Keep a store of seen ULIDs at least as long
  as `message_ttl_seconds`. ULIDs sort by arrival, so you can prune by
  timestamp.
- Also dedupe at the E2E layer. If a sender retries a deposit whose first
  attempt actually succeeded (response lost), the relay stores two messages
  with *different* `msg_id`s. Put an E2E message id inside the encrypted
  payload.
- **Process, then ack.** Persist or handle a message first, then
  `DELETE /v1/mailbox/{msg_id}`. Ack is idempotent.
- **Long-poll.** Use `GET /v1/mailbox?wait=25&max=32`. Re-issue it
  **immediately** after every response, including empty ones, so there is
  no delivery gap. The relay wakes parked polls within milliseconds of a
  deposit.
- **WebSocket** (`/v1/mailbox/ws`). The upgrade request is signed like a
  GET with an empty body. Server frames carry `{msg_id, deposited_at,
  payload}`, and you ack with `{"ack":"<msg_id>"}`. Unacked messages are
  pushed again after the visibility timeout. On close code 1001 (relay
  restarting), reconnect with backoff. Long-poll stays the mandatory
  fallback.
- A relay may limit concurrent collectors per mailbox. One long-poll **or**
  one socket per device is plenty.
- Mobile apps that can't hold a connection are woken by the push gateway.
  On wake, collect, decrypt locally, then ack (see PUSH-GATEWAY.md).

## 5. Errors, retries and backoff

| Response | What to do |
|---|---|
| `429 rate_limited` | Wait `retry_after` seconds (also in the `Retry-After` header) plus jitter, then retry. |
| `5xx`, network error | Retry with exponential backoff and full jitter, for example 0.25 s × 2ⁿ capped at about 30 s. Re-sign every attempt. |
| `timestamp_stale` | Fix the clock. Don't loop. |
| `replay_detected` | You resent an identical signed request. Re-sign with a new timestamp. |
| `token_expired` / `token_invalid` | Refresh the token from the recipient. Check `aud` against the relay URL. |
| `token_revoked` | Stop sending to this mailbox. Surface the error to the user. |
| `quota_exceeded` | The recipient's mailbox is full or your token's quota is spent. Back off for a long time and notify. |
| `payload_too_large` | Use the claim-check blob flow (§6) or split at the E2E layer. |
| `mailbox_unknown` | Wrong address, the mailbox isn't registered, or it was rotated away. Re-resolve over E2E. |

Never retry 4xx errors other than 429 unchanged.

## 6. Claim-check blob flow (files above `max_payload_bytes`)

1. Read `max_blob_bytes` from your registration `limits`, or from the
   recipient's advertised limits. If it's missing, the relay has no blob
   support.
2. Generate a fresh random 256-bit key. Encrypt the file with
   XChaCha20-Poly1305 and compute `content_hash`, the SHA-256 of the
   plaintext.
3. Upload with `PUT /v1/blob/{recipient_mailbox_id}`:
   - body: raw ciphertext
   - headers: `Content-Type: application/octet-stream`, the same deposit
     token, and a signature over SHA-256 of the ciphertext
   - response: `{blob_id, expires_at}`
4. Deposit an ordinary message whose **E2E-encrypted** payload carries
   `{blob_id, key, content_hash, filename, mime, size}`. Filename and MIME
   type must never appear anywhere the relay can see them.
5. The recipient collects the message and fetches
   `GET /v1/blob/{blob_id}` (signed as owner). It decrypts, verifies
   `content_hash`, persists the file in its own storage, and then sends
   `DELETE /v1/blob/{blob_id}`.
6. Blobs expire after `blob_ttl_seconds` (default 7 days), so fetch them
   promptly. Only the recipient mailbox's owner can fetch a blob. The
   sender can't read its own upload back.

## 7. Key rotation

1. Sign the current `mailbox_id` (its ASCII bytes) with the new key to make
   the proof.
2. With the current key, call `POST /v1/mailbox/rotate {new_pubkey,
   new_key_proof}`. The response is the new `mailbox_id`.
3. Collect from both mailboxes during the grace period (default 7 days).
4. Mint new tokens under the new key, announce the new address over E2E,
   and stop using old tokens. They die with the old mailbox.

## 8. Things clients must never do

- Never send plaintext payloads. Everything you deposit is already E2E
  ciphertext.
- Never put metadata in relay-visible fields: URLs, headers, or the blob
  `Content-Type` beyond `application/octet-stream`.
- Never share the relay key with the E2E or credential keys, or ship it off
  the device or enclave. The vault's parent instance forwards bytes and
  never holds the vault's relay key.
- Never log tokens, signatures or private keys.
