# vettid-relay

A small, vendor-neutral mailbox relay for VettID. It stores **opaque,
end-to-end-encrypted payloads** for recipients who alone decide who may
deposit, and moves them between vaults, apps and agents. The relay holds no
keys to payload content: a compromised relay can drop or delay messages, but
can't read or forge them.

- **Protocol:** [`docs/RELAY-PROTOCOL.md`](docs/RELAY-PROTOCOL.md)
  (**v0.4.0**, reported by `relay -version` and `/healthz`). This repository
  implements all of it:
  - registration
  - deposit tokens (PASETO v4.public, sender-bound), plus one-shot open
    tokens for first contact (§5.6)
  - deposit, and long-poll and WebSocket collect with the depositor's
    `sender` key
  - ack, denylist revocation and key rotation
  - the optional blob transfer (§6.8)
  - single-fetch claims for bootstrap bundles (§6.9)

  Every test vector in §9 is reproduced byte-for-byte in the tests.
- **Client guide:** [`docs/CLIENT-NOTES.md`](docs/CLIENT-NOTES.md).
- **Stack:** Go standard library `net/http`, pure-Go SQLite
  (`modernc.org/sqlite`, WAL), `github.com/coder/websocket`,
  `github.com/oklog/ulid/v2`. PASETO v4.public and the Prometheus exporter
  are implemented in-tree on `crypto/ed25519` and the standard library.
  There is no CGO, and the binary is static.
- **Two stores, one protocol.** `RELAY_STORE=sqlite` (default): one file,
  one process. `RELAY_STORE=dynamodb`: DynamoDB + S3 + Valkey, shared by any
  number of relay processes behind one URL (rolling deploys without
  downtime, autoscaling). Clients can't tell them apart; both pass the same
  conformance suite and the whole API test suite. For the shared store this
  adds the AWS SDK for Go v2 (DynamoDB, S3) and `valkey-go`.

## Quick start

```sh
make build                                   # bin/relay, bin/relayctl
RELAY_BASE_URL=http://localhost:8080 RELAY_DB_PATH=./relay.db ./bin/relay
./bin/relayctl -url http://localhost:8080 smoke   # end-to-end check
```

`relayctl smoke` registers two throwaway principals, then runs the main flow:
it mints a token, deposits a message, collects it by long-poll (and reports
the wake latency), and acks it. It then uploads, fetches and deletes a 1 MiB
blob. Next it runs first contact: it leaves a claim, a stranger fetches it
exactly once, the stranger deposits once with a one-shot open token, and
the collect shows the stranger as `sender`. Finally it revokes the sender
and checks that the next deposit is rejected.

Other `relayctl` commands run each step by hand: `keygen`, `register`,
`mint`, `mint-open`, `deposit`, `collect`, `revoke`, `blob-put`,
`blob-get`, `claim-put` and `claim-get`. Run `relayctl` with no arguments
for usage.

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
| `RELAY_STORE` | `sqlite` | `sqlite` (one process) or `dynamodb` (several processes on a shared store; see [Multi-process hosting](#multi-process-hosting)). |
| `RELAY_DB_PATH` | `relay.db` | SQLite database file (`/data/relay.db` in the image). `sqlite` only. |
| `RELAY_DYNAMODB_TABLE` | | DynamoDB table (`dynamodb`, required). Layout: `internal/store/dynamo`. |
| `RELAY_BLOB_BUCKET` | | S3 bucket for blob bodies (`dynamodb` with blobs enabled, required). |
| `RELAY_VALKEY_ADDR` | | Valkey `host:port` for the shared replay cache, rate limits and wake-on-deposit (`dynamodb`, required). |
| `RELAY_VALKEY_TLS` | `false` | TLS to Valkey (ElastiCache Serverless requires it). |
| `RELAY_VALKEY_IAM_USER` / `RELAY_VALKEY_CACHE_NAME` | | ElastiCache IAM authentication: user id and cache name for the SigV4 token (needs TLS; no password anywhere). |
| `RELAY_VALKEY_SERVERLESS` | `true` | The IAM token targets a serverless cache (`false` for a replication group). |
| `RELAY_VALKEY_PREFIX` | `relay` | Key and channel namespace. Processes serving one relay URL must share it. |
| `RELAY_EMPTY_HINTS` | `true` | With Valkey: collectors skip the store query for mailboxes known to be empty (see below). |
| `RELAY_EMPTY_SKIP_MAX` | `5m` | Longest time one "mailbox is empty" finding is trusted: the worst-case delivery delay if a deposit's hint update is lost. |
| `RELAY_DYNAMODB_ENDPOINT` / `RELAY_S3_ENDPOINT` | | Development and tests only (DynamoDB Local, a fake S3). AWS credentials and region come from the standard SDK chain (`AWS_REGION`, the ECS task role). |
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
| `RELAY_MAILBOX_MAX_BLOB_BYTES` | `67108864` | Per-mailbox storage cap (§8.8, §6.9). It counts blobs deposited to the mailbox plus claims the mailbox created. |
| `RELAY_MAILBOX_MAX_DENYLIST` | `10000` | Per-mailbox cap on live denylist entries. |
| `RELAY_ROTATION_GRACE` | `168h` (7 d) | How long a rotated-away mailbox keeps collecting before deletion (§6.7). |
| `RELAY_MAX_TOKEN_LIFETIME` | `720h` (30 d) | `max_token_lifetime_seconds` (§5.2). Sender-bound tokens with `exp − iat` above this are `token_invalid`. It also bounds denylist retention (§5.5). Any positive duration is accepted, for example `9600h` (400 d) for long-lived, low-quota reconnect tokens. |
| `RELAY_OPEN_TOKEN_MAX_LIFETIME` | `600s` | `open_token_max_lifetime_seconds` (§5.6). This is the cap on `exp − iat` for one-shot open tokens. Up to 7 days is recommended for remote invitations. |
| `RELAY_MAX_CLAIM_BYTES` | `16384` | `max_claim_bytes` (§6.9). This is the maximum claim body. |
| `RELAY_CLAIM_TTL` | `900s` | `claim_ttl_seconds` (§6.9). It's the longest TTL a creator may request with `PUT /v1/claim/ttl/<seconds>`. Up to 7 days is recommended. A bare `PUT /v1/claim` gets min(900 s, this). |
| `RELAY_RATE_IP_RPS` / `RELAY_RATE_IP_BURST` | `20` / `40` | Per-source-IP token bucket on `/v1/*`, applied before any parsing. The key is the IPv4 address or the IPv6 /64. |
| `RELAY_RATE_SENDER_RPS` / `RELAY_RATE_SENDER_BURST` | `5` / `20` | Per-sender bucket, applied to deposits and blob uploads. It's keyed by token `sub`, or by `jti` for open tokens. |
| `RELAY_RATE_CLAIM_GET_RPS` / `RELAY_RATE_CLAIM_GET_BURST` | `1` / `10` | Extra bucket for unauthenticated claim fetches, keyed by IPv4 address or IPv6 /64. It resists guessing and scraping. |
| `RELAY_MAX_COLLECTORS_PER_MAILBOX` | `4` | Concurrent long-polls plus WebSockets per mailbox. |
| `RELAY_REPLAY_CACHE_MAX` | `1000000` | Replay-cache capacity. When it's full, requests are shed with `rate_limited` and no live entries are evicted. |
| `RELAY_SWEEP_INTERVAL` | `60s` | TTL sweeper period. The first pass is jittered. |
| `RELAY_SHUTDOWN_TIMEOUT` | `20s` | Bound on the graceful drain after SIGTERM. |

## Deployment notes

> **SQLite: single writer.** A relay database must be opened by **exactly one**
> relay process. All writes go through one SQLite connection. That is how
> per-mailbox ULID order equals arrival order and how quotas stay atomic.
> Never point two instances (or two tasks during a rolling deploy) at the
> same file, and never put the file on a network filesystem shared by
> concurrent writers. Configure the container platform to stop the old task
> before it starts the new one. To run several processes for one relay URL,
> use `RELAY_STORE=dynamodb` instead.

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

## Multi-process hosting

With `RELAY_STORE=dynamodb` any number of relay processes serve one relay
URL. Nothing about the protocol changes; what one process accepts, every
other process sees, refuses or is woken by.

- **State** is one DynamoDB table (on-demand, TTL attribute `ttl_s`, a
  KEYS_ONLY GSI `due` on `gpk`/`gsk`; `dynamo.CreateTable` is the reference
  definition). Every operation that SQLite does in one transaction is a
  DynamoDB transaction or a single conditional write: deposit + quotas +
  open-token consumption + ULID order; leasing on collect; claim single
  fetch; rotation. Decisions use strongly consistent reads. Expiry is
  checked on every read; TTL only reclaims space. A message is one item
  (the payload as binary), so `RELAY_MAX_PAYLOAD_BYTES` is capped at
  380,000 with this store.
- **Blob bodies** are S3 objects `blobs/<mailbox>/<blob id>`; metadata and
  the storage quota are in DynamoDB. Give the bucket a lifecycle rule that
  expires objects a day after `RELAY_BLOB_TTL` (deleted or purged blobs are
  removed directly).
- **Valkey** holds the replay cache (`SET NX PX`, 91 s), the rate-limit
  buckets (one GCRA script on Valkey's clock), and wake-on-deposit signals
  (sharded pub/sub). If Valkey is unreachable, signed requests are shed with
  `429 rate_limited` (a replay is never admitted unchecked), rate limits
  fall back to per-process buckets, and parked collectors re-check the
  store every 5 s. A lost wake signal delays delivery at most until the
  collector's next re-check; it never loses a message.
- **Empty hints.** Always-on collectors re-poll every 25 s, so most
  collects find nothing. Valkey keeps, per mailbox, a deposit version `v`
  (bumped by every deposit *after* its store commit and *before* its wake
  signal) and the version `e` at which a real, strongly consistent query
  last found the mailbox empty, valid until `u`. A collector registers for
  wake-ups, then skips the store only if `e == v` and `u` has not passed.
  `e` is written only if `v` did not change across the query, and `u` is at
  most the moment a leased message can reappear and at most
  `RELAY_EMPTY_SKIP_MAX` later. So a deposit is never skipped unless its
  bump was lost after the store commit (process crash, Valkey failover), and
  then for at most `RELAY_EMPTY_SKIP_MAX`. Any Valkey error, an unsubscribed
  wake bus, or a forced re-check (resubscribe, Valkey outage) means a real
  query. A real query that finds messages clears the hint. Metrics:
  `relay_collect_store_queries_total`, `relay_collect_store_skips_total`,
  `relay_empty_hint_bump_failures_total`.
- **Per-process limits.** `RELAY_MAX_COLLECTORS_PER_MAILBOX`,
  `RELAY_MAX_CONCURRENT_BLOB_TRANSFERS` and the replay-cache capacity bound
  each process's own resources.
- **Mailbox quotas** are counters updated in the same transaction as the
  write. Acks, expiry and TTL deletions can leave them high; a failing quota
  check recomputes them from the items (at most once a minute per
  mailbox), so the observable limit is the same as with SQLite. Token quotas
  are exact.
- **Deploys.** Processes can start and stop at any time. On SIGTERM a
  process drains as described above; give the load balancer a
  deregistration delay longer than a long-poll (25 s) so clients move to
  other processes without errors.
- **Sweeper.** Each process sweeps; the only work left for it is purging
  rotated mailboxes 10 minutes after their grace period (the cascade
  SQLite does with foreign keys). Purges are idempotent.

## API summary

| Method and path | Auth | Success |
|---|---|---|
| `POST /v1/register` | signed by the key being registered | `201` (new) or `200` (existing): `{mailbox_id, limits}` |
| `POST /v1/mailbox/{mailbox_id}` | deposit token + signed by token `sub` (open token: any signer) | `201 {msg_id}` |
| `GET /v1/mailbox?wait=0..25&max=1..100` | owner | `200 {messages:[{msg_id, deposited_at, sender, payload}]}` (defaults: `wait=0`, `max=32`) |
| `GET /v1/mailbox/ws` | owner (at upgrade) | WebSocket: server frames are messages, client frames are `{"ack": "<msg_id>"}` |
| `DELETE /v1/mailbox/{msg_id}` | owner | always `204`, including for another mailbox's message (a no-op) |
| `POST /v1/mailbox/denylist` | owner | `204` |
| `POST /v1/mailbox/rotate` | owner (current key) | `200 {mailbox_id}` |
| `PUT /v1/blob/{mailbox_id}` | deposit token + signed by `sub` | `201 {blob_id, expires_at}` |
| `GET /v1/blob/{blob_id}` | owner of the recipient mailbox | `200 application/octet-stream` |
| `DELETE /v1/blob/{blob_id}` | owner | `204` (idempotent) |
| `PUT /v1/claim` | signed by a registered mailbox key | `201 {claim_id, expires_at}` |
| `GET /v1/claim/{claim_id}` | none (rate-limited) | `200 application/octet-stream`. Single fetch: the claim is deleted. |
| `DELETE /v1/claim/{claim_id}` | the creating key | `204` (idempotent) |
| `GET /healthz` | none | `200` when the DB is reachable and not draining, else `503` |

Error bodies are `{"code", "message", "retry_after"?}`. HTTP statuses follow
the spec's §7.1 table exactly, and a test parses the table from the spec to
keep them in step:

| Status | Codes |
|---|---|
| 400 | `bad_request` |
| 401 | `signature_invalid`, `timestamp_stale`, `replay_detected`, `token_invalid`, `token_expired` |
| 403 | `token_revoked` |
| 404 | `mailbox_unknown`, `blob_unknown`, `claim_unknown`, `not_found` |
| 409 | `token_used` |
| 413 | `payload_too_large` |
| 429 | `quota_exceeded`; `rate_limited` (with `Retry-After`) |
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
- **No existence oracles.** Every lookup below answers the same way
  whether or not the target exists:
  - Deposits to unknown mailboxes get a byte-identical `mailbox_unknown`
    whatever the token. Owner routes signed by an unregistered key get the
    same response.
  - Unknown, expired and other-mailbox blobs get an identical
    `blob_unknown`.
  - Unknown, expired, deleted and already-fetched claims get an identical
    `claim_unknown`.
  - Ack is always `204`.
- **One-shot open tokens** (§5.6) are consumed atomically with the
  deposit. The record is stored in SQLite until the token's `exp`, so a
  second use is `token_used` even after a restart or a Litestream restore.
  The signer becomes the message's `sender`.
- **Claims** (§6.9) have 128-bit ids drawn from `crypto/rand`. The ids are
  never logged and never appear in metrics: the access log records the
  route pattern only. A claim is fetched and deleted in one SQL statement,
  so concurrent fetches can't both succeed.
- **Blobs.** Blob bytes are never parsed or logged. Storage is capped per
  mailbox, and blob metadata (filename, type) never reaches the relay.
- **Cryptography.** Relay keys and deposit tokens stay Ed25519 / PASETO
  v4.public. Post-quantum migration of this layer is deliberately deferred
  (PQC-MIGRATION Phase 3). The relay never sees payload cryptography.

## Spec interpretation notes

Version 0.3.0 of the spec settled most of the questions raised against 0.2:
fractional-second timestamps used verbatim (§4.1), the uniform `204` ack
(§6.5), `iat` strictness and backdating (§5.2), the size check coming first
(§5.3), collect defaults (§6.3), the complete code and status table (§7.1),
and `sub`-revocation semantics (§5.5). Where the spec is still silent, this
implementation chooses as follows:

- **Rotation proof** (§6.7) is an Ed25519 signature by the new key over the
  ASCII bytes of the current `mailbox_id`. During the grace period the old
  mailbox keeps accepting deposits and collects, and it's deleted (with
  its tokens' effect) afterwards.
- **Denylist retention** (§5.5) is the time of revocation, plus the larger
  of `RELAY_MAX_TOKEN_LIFETIME` and `RELAY_OPEN_TOKEN_MAX_LIFETIME`, plus
  the freshness window.
- **Open tokens and blobs.** One-shot open tokens are refused for
  `PUT /v1/blob` with `token_invalid`. §5.6 grants "exactly one deposit".
  §6.8 says blob authorization is "identical to deposit", but letting a
  bearer token upload a large blob is not needed for first contact, so the
  relay refuses it.
- **Open tokens and rate limits.** For open tokens, the per-sender rate
  bucket is keyed by the token's `jti`, because the signer is known only
  after §5.3 step 7.
- **Claim TTL.** The TTL is part of the signed path
  (`PUT /v1/claim/ttl/<seconds>`, canonical decimal between 1 and
  `claim_ttl_seconds`). Anything else is `bad_request`; it is not clamped.
  The unsigned `X-VettID-Claim-TTL` header from an early 0.3 draft is
  refused with `bad_request`.
- **Claim limits.** Empty claim bodies are `bad_request`. Claims count
  toward the creating mailbox's `RELAY_MAILBOX_MAX_BLOB_BYTES`, together
  with blobs deposited to it.
- **Blob storage.** With SQLite, blobs are kept in the database file (a
  separate table behind the `BlobStore` interface) rather than as files on
  disk, which §6.8 says SHOULD be used. This is deliberate: one file is the
  entire state for replication. With DynamoDB, blob bodies are S3 objects,
  outside the message store as §6.8 recommends.
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
make test-dynamo   # starts DynamoDB Local + Valkey (memory-capped containers),
                   # runs the shared-store tests, then removes the containers
```

`make test-dynamo` runs the store conformance suite on DynamoDB, the Valkey
coordination tests, the whole API suite on DynamoDB, and a two-process e2e
(the relay binary started twice on one table and one Valkey): wake-on-deposit
across processes for long-poll and WebSocket, one open token raced from both
processes, one claim fetched concurrently from both, a request replayed to
the other process, a shared rate limit, and a process stopping mid-test.

Layout:

- `cmd/relay`: the server.
- `cmd/relayctl`: the CLI client.
- `internal/api`: handlers, middleware and authorization.
- `relayauth` (public): mailbox ids, signed requests, replay cache and PASETO v4.public.
- `internal/store`: the `Backend` interface and the SQLite store, including blobs.
- `internal/store/dynamo`: the DynamoDB + S3 store; `internal/store/storetest`: the conformance suite both stores pass.
- `internal/coord`: Valkey replay cache, rate limits and wake-on-deposit for multi-process relays.
- `internal/sweep`: the TTL sweeper.
- `internal/ratelimit`, `internal/metrics` and `internal/config`.
- `relayclient` (public): the reference client, imported by vettid-vault. Inject `HTTP` to change transport (e.g. a vsock dialer).
- `test/e2e`: the two-principal integration test, and the two-process test on the shared store.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
