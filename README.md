# vettid-relay

A small, vendor-neutral mailbox relay for VettID. It stores **opaque,
end-to-end-encrypted payloads** for recipients who alone decide who may
deposit, and moves them between vaults, apps and agents. The relay holds no
keys to payload content: a compromised relay can drop or delay messages, but
can't read or forge them.

- **Protocol:** [`docs/RELAY-PROTOCOL.md`](docs/RELAY-PROTOCOL.md) (v0.2.0).
  This repository implements all of it: registration, deposit tokens
  (PASETO v4.public, sender-bound), deposit, long-poll and WebSocket collect,
  ack, denylist revocation, key rotation, and the optional blob transfer
  (§6.8). Every test vector in §9 is reproduced byte-for-byte in the tests.
- **Client guide:** [`docs/CLIENT-NOTES.md`](docs/CLIENT-NOTES.md).
- **Stack:** Go standard library `net/http`, pure-Go SQLite
  (`modernc.org/sqlite`, WAL), `github.com/coder/websocket`,
  `github.com/oklog/ulid/v2`. PASETO v4.public and the Prometheus exporter
  are implemented in-tree on `crypto/ed25519` and the standard library.
  There is no CGO, and the binary is static.

## Quick start

```sh
make build                                   # bin/relay, bin/relayctl
RELAY_BASE_URL=http://localhost:8080 RELAY_DB_PATH=./relay.db ./bin/relay
./bin/relayctl -url http://localhost:8080 smoke   # end-to-end check
```

`relayctl smoke` registers two throwaway principals, then runs the main flow:
it mints a token, deposits a message, collects it by long-poll (and reports
the wake latency), and acks it. It then uploads, fetches and deletes a 1 MiB
blob, revokes the sender, and checks that the next deposit is rejected. Other
`relayctl` commands (`keygen`, `register`, `mint`, `deposit`, `collect`,
`revoke`, `blob-put`, `blob-get`) run each step by hand. Run `relayctl` with
no arguments for usage.

## Container

```sh
docker build --build-arg VERSION=$(git rev-parse --short HEAD) -t vettid-relay .
docker buildx build --platform linux/amd64,linux/arm64 -t vettid-relay .
docker run -p 8080:8080 -v relay-data:/data -e RELAY_BASE_URL=https://relay.example.org vettid-relay
```

- Distroless `static-debian13:nonroot` base, pinned by digest. The image is
  about 15 MB and runs as uid/gid 65532.
- The binary path is stable: **`/relay`**.
- **Health check command:** `/relay -healthcheck`. It GETs
  `http://127.0.0.1:<port of RELAY_LISTEN_ADDR>/healthz` with a 3 s timeout
  and exits 0 on HTTP 200, 1 otherwise. It needs no shell or curl. Use it
  as the container platform's health check, for example ECS
  `["CMD", "/relay", "-healthcheck"]`.
- State lives in `/data/relay.db` (and its `-wal`/`-shm` files). Mount
  persistent storage at `/data`.
- The database file is created in WAL mode **before** the listeners start,
  so it exists by the time `/healthz` first returns 200. A replication
  sidecar such as Litestream can wait on the relay's health.

## Configuration

All configuration is through environment variables. The relay holds no
secrets, so none of these are sensitive. Durations accept Go syntax (`90s`,
`336h`) or a bare integer number of seconds.

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_LISTEN_ADDR` | `:8080` | Public HTTP listen address. |
| `RELAY_BASE_URL` | `http://localhost:8080` | Public base URL of this relay, for example `https://relay.vettid.org`. Deposit-token `aud` must equal it **exactly**, so leave off any trailing slash. |
| `RELAY_DB_PATH` | `relay.db` | SQLite database file (`/data/relay.db` in the image). |
| `RELAY_TRUST_PROXY` | `false` | `true` means the client IP is the **last** `X-Forwarded-For` hop, which is the one the load balancer (AWS ALB) appends. Earlier hops are client-controlled and ignored. Enable this only behind a proxy that always appends. |
| `RELAY_METRICS_ADDR` | `127.0.0.1:9090` | Prometheus `/metrics` listener. It must differ from the public address; an empty value disables it. Never expose it publicly. |
| `RELAY_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |
| `RELAY_MAX_PAYLOAD_BYTES` | `262144` | Max decoded deposit payload (`max_payload_bytes`). |
| `RELAY_MESSAGE_TTL` | `336h` (14 d) | Lifetime of an unacked message (`message_ttl_seconds`). |
| `RELAY_VISIBILITY_TIMEOUT` | `60s` | Lease length for collected, unacked messages (`visibility_timeout_seconds`). |
| `RELAY_BLOBS_ENABLED` | `true` | Serve `/v1/blob` (§6.8) and advertise blob limits at registration. |
| `RELAY_MAX_BLOB_BYTES` | `8388608` | Max blob size (`max_blob_bytes`), enforced while streaming. |
| `RELAY_BLOB_TTL` | `168h` (7 d) | Blob lifetime (`blob_ttl_seconds`). |
| `RELAY_MAX_CONCURRENT_BLOB_TRANSFERS` | `8` | Concurrent blob uploads plus downloads. Each can hold up to `max_blob_bytes` in memory. |
| `RELAY_MAILBOX_MAX_MESSAGES` | `10000` | Per-mailbox cap on stored messages (`quota_exceeded`). |
| `RELAY_MAILBOX_MAX_BYTES` | `134217728` | Per-mailbox cap on stored payload bytes. |
| `RELAY_MAILBOX_MAX_BLOB_BYTES` | `67108864` | Per-mailbox blob storage cap (§8.8). |
| `RELAY_MAILBOX_MAX_DENYLIST` | `10000` | Per-mailbox cap on live denylist entries. |
| `RELAY_ROTATION_GRACE` | `168h` (7 d) | How long a rotated-away mailbox keeps collecting before deletion (§6.7). |
| `RELAY_MAX_TOKEN_LIFETIME` | `720h` (30 d) | Relay policy: tokens with `exp − iat` above this are `token_invalid`. This bounds denylist retention (§5.5). |
| `RELAY_RATE_IP_RPS` / `RELAY_RATE_IP_BURST` | `20` / `40` | Per-source-IP token bucket on `/v1/*`, applied before any parsing. The key is the IPv4 address or the IPv6 /64. |
| `RELAY_RATE_SENDER_RPS` / `RELAY_RATE_SENDER_BURST` | `5` / `20` | Per-sender bucket keyed by token `sub`, applied to deposits and blob uploads. |
| `RELAY_MAX_COLLECTORS_PER_MAILBOX` | `4` | Concurrent long-polls plus WebSockets per mailbox. |
| `RELAY_REPLAY_CACHE_MAX` | `1000000` | Replay-cache capacity. When it's full, requests are shed with `rate_limited` and no live entries are evicted. |
| `RELAY_SWEEP_INTERVAL` | `60s` | TTL sweeper period. The first pass is jittered. |
| `RELAY_SHUTDOWN_TIMEOUT` | `20s` | Bound on the graceful drain after SIGTERM. |

## Deployment notes

> **Single writer.** A relay database must be opened by **exactly one**
> relay process. All writes go through one SQLite connection. That is how
> per-mailbox ULID order equals arrival order and how quotas stay atomic.
> Never point two instances (or two tasks during a rolling deploy) at the
> same file, and never put the file on a network filesystem shared by
> concurrent writers. To scale, run more relays and assign mailboxes to
> them (spec §1). Configure the container platform to stop the old task
> before it starts the new one.

- **Graceful shutdown.** On SIGTERM or SIGINT, `/healthz` switches to 503
  and parked long-polls return `{"messages":[]}` immediately. WebSockets are
  closed with 1001 (going away), in-flight requests finish, and the sweeper
  stops. The database closes last. All of this happens within
  `RELAY_SHUTDOWN_TIMEOUT`, so set the platform's stop timeout above it
  (for example ECS `stopTimeout` of 30 s).
- **TLS.** Run the relay behind a TLS-terminating proxy (for example an
  ALB), with `RELAY_TRUST_PROXY=true` so rate limits use real client
  addresses. WebSocket collect needs the proxy to allow upgrades and idle
  connections of at least about 60 s. The relay pings every 30 s.
- **Backups and replication.** The single SQLite file (WAL mode) is the
  relay's whole state: mailboxes, messages, denylists, quota counters and
  blobs. Replicate it with Litestream or similar. Losing it loses only
  undelivered ciphertext and registrations, and re-registration is
  self-service.
- **Metrics.** `/metrics` is served only on `RELAY_METRICS_ADDR`, which is
  loopback by default. A sidecar in the same network namespace (for
  example an ECS awsvpc task) can scrape it. The relay exports these series:
  - deposits and deposit bytes
  - collects and collected messages
  - acks, registrations, revocations and rotations
  - blob puts, gets and deletes, and blob bytes
  - errors, by canonical code
  - parked collectors, WebSocket sessions and active collectors
  - replay-cache size
  - sweeps, and rows removed by kind
  - the draining flag
- **Logs.** Logs are JSON on stdout, one access line per request. Each line
  has the route *pattern* (never the raw path, which contains ids), status,
  error code, sizes, duration and, where relevant, the `msg_id` or
  `blob_id`. Payloads, blob bytes, tokens, signatures, public keys, mailbox
  ids and client IPs are never logged. A test enforces this.

## API summary

| Method and path | Auth | Success |
|---|---|---|
| `POST /v1/register` | signed by the key being registered | `201` (new) or `200` (existing): `{mailbox_id, limits}` |
| `POST /v1/mailbox/{mailbox_id}` | deposit token + signed by token `sub` | `201 {msg_id}` |
| `GET /v1/mailbox?wait=0..25&max=1..100` | owner | `200 {messages:[{msg_id, deposited_at, payload}]}` (defaults: `wait=0`, `max=32`) |
| `GET /v1/mailbox/ws` | owner (at upgrade) | WebSocket: server frames are messages, client frames are `{"ack": "<msg_id>"}` |
| `DELETE /v1/mailbox/{msg_id}` | owner | `204` (idempotent) |
| `POST /v1/mailbox/denylist` | owner | `204` |
| `POST /v1/mailbox/rotate` | owner (current key) | `200 {mailbox_id}` |
| `PUT /v1/blob/{mailbox_id}` | deposit token + signed by `sub` | `201 {blob_id, expires_at}` |
| `GET /v1/blob/{blob_id}` | owner of the recipient mailbox | `200 application/octet-stream` |
| `DELETE /v1/blob/{blob_id}` | owner | `204` (idempotent) |
| `GET /healthz` | none | `200` when the DB is reachable and not draining, else `503` |

Error bodies are `{"code", "message", "retry_after"?}` (§7.1). HTTP status by
code:

| Status | Codes |
|---|---|
| 401 | `token_invalid`, `token_expired`, `signature_invalid`, `timestamp_stale`, `replay_detected` |
| 403 | `token_revoked`, `quota_exceeded` |
| 404 | `mailbox_unknown`, `blob_unknown`, `not_found` |
| 413 | `payload_too_large` |
| 429 | `rate_limited`, with `Retry-After` |
| 400 | `bad_request` |
| 500 | `internal` |

## Security notes (spec §8)

- **Order of checks.** Body-size limits apply before signature
  verification, and the per-IP rate limit applies before any header, token
  or body parsing. Deposits follow §5.3 exactly. Blob uploads run §5.3
  steps 1–6 on headers alone, so unauthorized uploads are refused before
  their body is read, and the body is then streamed with the limit enforced
  while reading.
- **Signature before writes.** Signatures, sender binding
  (`X-VettID-Key == sub`), the ±90 s freshness window and the replay cache
  all come before any database write. Key comparisons are constant-time.
- **Fixed error messages.** Messages are fixed per code and never echo
  request content.
- **No existence oracles.** Deposits to unknown mailboxes get a
  byte-identical `mailbox_unknown` whatever the token. Owner routes signed
  by an unregistered key get the same response. Unknown, expired and
  other-mailbox blobs get an identical `blob_unknown`. The one exception
  is ack, described in the next section.
- **Blobs.** Blob bytes are never parsed or logged. Storage is capped per
  mailbox, and blob metadata (filename, type) never reaches the relay.
- **Cryptography.** Relay keys and deposit tokens stay Ed25519 / PASETO
  v4.public. Post-quantum migration of this layer is deliberately deferred
  (PQC-MIGRATION Phase 3). The relay never sees payload cryptography.

## Spec interpretation notes

Where the spec is silent or ambiguous, this implementation chooses as
follows:

- **Sub-second timestamps.** The canonical string doesn't cover the query
  string, and Ed25519 is deterministic. Two requests with the same method,
  path, body and timestamp therefore have the same signature, and the
  replay cache rejects the second. Clients should send RFC 3339 timestamps
  with fractional seconds (accepted by the relay, and emitted by
  `internal/client`), especially when they re-issue long-polls back-to-back.
- **Ack of another mailbox's message** returns `404 mailbox_unknown`, as
  §6.5 literally specifies. A nonexistent message returns `204`. That
  difference reveals whether a ULID exists in *some* mailbox. ULIDs carry
  80 random bits from `crypto/rand`, so the risk is small, but it's flagged
  for spec review.
- **Rotation proof** (§6.7) is an Ed25519 signature by the new key over the
  ASCII bytes of the current `mailbox_id`. During the grace period the old
  mailbox keeps accepting deposits and collects, and it's deleted (with
  its tokens' effect) afterwards.
- **Denylist retention** (§5.5) is the time of revocation plus
  `RELAY_MAX_TOKEN_LIFETIME` plus the freshness window. To keep this safe,
  the relay refuses tokens whose `exp − iat` exceeds the max lifetime. A
  `sub` entry also blocks tokens minted for that sender after the
  revocation until the entry expires.
- **`iat` check.** `iat ≤ now < exp` is applied strictly, with no skew
  allowance, as written. Issuers should backdate `iat` slightly if their
  clock may run ahead of the relay's.
- **Non-canonical codes.** `bad_request` (400) covers malformed JSON,
  base64 or parameters, and `not_found` (404) covers unrouted paths. The
  spec's code list doesn't cover these cases.
- **Size limit before mailbox lookup.** An oversized deposit body is
  rejected with `payload_too_large` before the §5.3 mailbox lookup (§8.5:
  size limits first).
- **Collect defaults.** `wait` defaults to 0 (return immediately) and `max`
  defaults to 32. Values above the caps are clamped.
- **Blob storage.** Blobs are kept in the SQLite file (a separate table
  behind the `BlobStore` interface) rather than as files on disk, which
  §6.8 says SHOULD be used. This is deliberate: one file is the entire
  state for replication.
- **Revoked `jti` and `sub` values** are checked against the token's own
  claims. `sub` values are canonicalised (strict padded base64 of the
  32-byte key).

## Development

```sh
make test          # go test ./...
make race          # go test -race ./...
make lint          # go vet + staticcheck (pinned, via go run)
make fuzz          # each fuzz target for FUZZTIME (default 20s)
make scan          # gitleaks over history
make image         # docker build
```

Layout:

- `cmd/relay`: the server.
- `cmd/relayctl`: the CLI client.
- `internal/api`: handlers, middleware and authorization.
- `internal/auth`: mailbox ids, signed requests, replay cache and PASETO.
- `internal/store`: SQLite, including blobs.
- `internal/sweep`: the TTL sweeper.
- `internal/ratelimit`, `internal/metrics` and `internal/config`.
- `internal/client`: the reference client.
- `test/e2e`: the two-principal integration test.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
