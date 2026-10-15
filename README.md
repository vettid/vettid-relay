# vettid-relay

A small, vendor-neutral mailbox relay for VettID. It stores **opaque,
end-to-end-encrypted payloads** for recipients who alone decide who may
deposit, and moves them between vaults, apps and agents. The relay holds no
keys to payload content: a compromised relay can drop or delay messages, but
can't read or forge them.

- **Protocol:** [`docs/RELAY-PROTOCOL.md`](docs/RELAY-PROTOCOL.md)
  (**v0.7.0**, reported by `relay -version` and `/healthz`). This repository
  implements all of it:
  - registration
  - deposit tokens (PASETO v4.public, sender-bound), plus one-shot open
    tokens for first contact (§5.6)
  - deposit, and long-poll and WebSocket collect with the depositor's
    `sender` key
  - ack, denylist revocation and key rotation
  - owner-signed mailbox deletion with re-registration tombstones (§6.10)
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
the collect shows the stranger as `sender`. It revokes the sender and
checks that the next deposit is rejected. Finally (relay ≥ 0.5.0) it
deletes the owner's mailbox while a long-poll is parked on it, checks that
the long-poll ends with `mailbox_unknown` and a fresh token's deposit is
refused, and deletes the sender's mailbox too, so a smoke run against a live
relay leaves only the stranger's unregistered key behind. Against an older
relay the deletion steps are skipped.

Other `relayctl` commands run each step by hand: `keygen`, `register`,
`mint`, `mint-open`, `deposit`, `collect`, `revoke`, `blob-put`,
`blob-get`, `claim-put`, `claim-get` and `delete-mailbox` (which takes
`-confirm <mailbox id>` as a guard). Run `relayctl` with no arguments
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
| `RELAY_LOG_INFO_RPS` / `RELAY_LOG_INFO_BURST` | `100` / `1000` | Log budget per relay process: info lines beyond it are dropped and counted (`log_dropped` in the `rate limits` line, `relay_log_lines_dropped_total`). The access lines of successful requests that change a mailbox's state (register, rotate, denylist, delete mailbox) have a second budget of the same size that other lines can't use up. Never dropped: the `rate limits` line (production alarms when it goes missing) and the process's start, drain and stop lines. Warn and error lines are not budgeted, but one message with the same `err`, `route` and `panic` values is written at most once per 10 s; the next one carries `repeated` (`log_suppressed`, `relay_log_lines_suppressed_total`). |
| `RELAY_MAX_PAYLOAD_BYTES` | `262144` | Max decoded deposit payload (`max_payload_bytes`). |
| `RELAY_MESSAGE_TTL` | `336h` (14 d) | Lifetime of an unacked message (`message_ttl_seconds`). An expired message is never delivered, but with the DynamoDB store its item stays stored until DynamoDB's TTL deletes it, typically within a few days of expiry. |
| `RELAY_VISIBILITY_TIMEOUT` | `60s` | Lease length for collected, unacked messages (`visibility_timeout_seconds`). |
| `RELAY_BLOBS_ENABLED` | `true` | Serve `/v1/blob` (§6.8) and advertise blob limits at registration. |
| `RELAY_MAX_BLOB_BYTES` | `8388608` | Max blob size (`max_blob_bytes`), enforced while streaming. |
| `RELAY_BLOB_TTL` | `168h` (7 d) | Blob lifetime (`blob_ttl_seconds`). |
| `RELAY_MAX_CONCURRENT_BLOB_TRANSFERS` | `8` | Concurrent blob uploads plus downloads, per relay process. Each can hold up to `max_blob_bytes` in memory. Uploads may use all but `RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX` of them (6 by default): the rest are kept for downloads. An upload takes its slot only once its body has begun to arrive. Beyond it, `429 rate_limited` with `retry_after` 2. |
| `RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX` | `2` | Uploads to one mailbox, and separately downloads by its owner, at a time per process; besides, one sender key has at most one upload to a mailbox at a time. Senders therefore can't keep an owner from its blobs. At least 1 and less than `RELAY_MAX_CONCURRENT_BLOB_TRANSFERS`. Beyond it, `429 rate_limited` with `retry_after` 2. |
| `RELAY_BLOB_PACE_BYTES` | `16384` | A blob body, up or down, must move at least this many bytes in every 5 s, or the transfer is dropped (an upload is answered `400` with the connection closed) and its slot freed. No transfer takes longer than 5 minutes (an 8 MiB blob needs 28 KiB/s). |
| `RELAY_MAILBOX_MAX_MESSAGES` | `10000` | Per-mailbox cap on stored messages (`quota_exceeded`). |
| `RELAY_MAILBOX_MAX_BYTES` | `33554432` (32 MiB) | Per-mailbox cap on stored payload bytes (`quota_exceeded`); `0` means no cap. At least `RELAY_MAX_PAYLOAD_BYTES`. A mailbox that already holds more (the default was 128 MiB) keeps its messages and is collected as before; deposits to it are refused until acks or expiry bring it under the cap. |
| `RELAY_MAILBOX_MAX_BLOB_BYTES` | `67108864` | Per-mailbox storage cap (§8.8, §6.9). It counts blobs deposited to the mailbox plus claims the mailbox created. |
| `RELAY_MAILBOX_MAX_DENYLIST` | `10000` | Per-mailbox cap on live denylist entries. |
| `RELAY_ROTATION_GRACE` | `168h` (7 d) | How long a rotated-away mailbox keeps collecting before deletion (§6.7). |
| `RELAY_MAX_TOKEN_LIFETIME` | `720h` (30 d) | `max_token_lifetime_seconds` (§5.2). Sender-bound tokens with `exp − iat` above this are `token_invalid`. It also bounds denylist retention (§5.5). Any positive duration is accepted, for example `9600h` (400 d) for long-lived, low-quota reconnect tokens. |
| `RELAY_OPEN_TOKEN_MAX_LIFETIME` | `600s` | `open_token_max_lifetime_seconds` (§5.6). This is the cap on `exp − iat` for one-shot open tokens. Up to 7 days is recommended for remote invitations. |
| `RELAY_MAX_CLAIM_BYTES` | `16384` | `max_claim_bytes` (§6.9). This is the maximum claim body. |
| `RELAY_CLAIM_TTL` | `900s` | `claim_ttl_seconds` (§6.9). It's the longest TTL a creator may request with `PUT /v1/claim/ttl/<seconds>`. Up to 7 days is recommended. A bare `PUT /v1/claim` gets min(900 s, this). |
| `RELAY_RATE_IP_RPS` / `RELAY_RATE_IP_BURST` | `100` / `300` | Flood guard on `/v1/*` per client network (the IPv4 address or the IPv6 /64), applied before any parsing. One address may carry a whole vault host: see [Rate limiting](#rate-limiting) for when to raise it. |
| `RELAY_RATE_KEY_RPS` / `RELAY_RATE_KEY_BURST` | `20` / `100` | Per-key bucket, applied once a request is authenticated: owner routes, registration and mailbox deletion. Keyed by the signing key. |
| `RELAY_RATE_REGISTER_RPS` / `RELAY_RATE_REGISTER_BURST` | `1` / `30` | New mailboxes (registrations that create one, and rotations) per client network. Registering an existing key again is free. |
| `RELAY_RATE_SENDER_RPS` / `RELAY_RATE_SENDER_BURST` | `5` / `20` | Per-sender bucket, applied to deposits after the request signature verifies (§5.3 step 7) and to blob uploads before their body is read. It's keyed by token `sub`, or by `jti` for open tokens. |
| `RELAY_RATE_CLAIM_GET_RPS` / `RELAY_RATE_CLAIM_GET_BURST` | `1` / `10` | Extra bucket for unauthenticated claim fetches, keyed by IPv4 address or IPv6 /64. It resists guessing and scraping. |
| `RELAY_RATE_IP_BYTES_PER_SEC` / `RELAY_RATE_IP_BYTES_BURST` | `262144` / `8388608` (256 KiB/s, 8 MiB) | Byte budget per client network for what it asks the relay to store: deposits (charged with their declared length after the token verified, before the body is read; without a `Content-Length`, the largest deposit body) and claims (charged once the claim is authenticated). A deposit or claim that is then not stored (quota, signature, malformed body, store error) gets its charge back. Over it, `429 rate_limited` with `retry_after`, the body unread. Per relay process. The burst must hold the largest deposit body and `RELAY_MAX_CLAIM_BYTES`. |
| `RELAY_RATE_BLOB_KEY_BYTES_PER_SEC` / `RELAY_RATE_BLOB_KEY_BYTES_BURST` | `1048576` / `33554432` (1 MiB/s, 32 MiB) | Byte budget for blobs per key: for an upload the sender's key (the token's `sub`, proved by the request signature only after the body), for a download the mailbox owner's (proved first). Each vault of a vault host has its own. An upload is refused unread if its key's budget is empty, but charged to it only once the signature has verified, with the bytes received (into debt if need be), so a token naming someone else's key can't spend that key's budget. The burst holds four blobs of the maximum size. Must hold `RELAY_MAX_BLOB_BYTES`. |
| `RELAY_RATE_BLOB_BYTES_PER_SEC` / `RELAY_RATE_BLOB_BYTES_BURST` | `8388608` / `268435456` (8 MiB/s, 256 MiB) | The ceiling over all keys of one client network, charged for uploads with the declared length (or `RELAY_MAX_BLOB_BYTES` without one) after the per-sender limit, before the body is read, and for downloads together with the owner's key budget (the blob's size, at most a key's burst, after the owner's signature verified; an empty budget refuses a download before the store is read; a download refused by one is charged to neither). An upload that stores nothing gets back only the part of its charge it never sent: every byte that reached the relay stays charged, whatever refused it (body failure, signature, quota, store). One refused a transfer slot (it held none) gets everything back. Over it, `429 rate_limited` with `retry_after`. Per relay process. With blobs enabled the ceiling's rate and burst must be at least a key's; every rate and burst must be greater than zero regardless. |
| `RELAY_RATE_WEB_RPS` / `RELAY_RATE_WEB_BURST` | `2` / `20` | Per-source-IP bucket for the web endpoints (§6.11) and every other path outside `/v1/` except `/healthz`. It's separate from the API bucket, so scanners never use up mailbox traffic's budget, and always in-process (per relay process, no Valkey round trip). |
| `RELAY_ANDROID_PACKAGE` | `com.vettid.app` | `package_name` in `/.well-known/assetlinks.json`. |
| `RELAY_ANDROID_CERT_SHA256` | the official VettID app's signing keys | Comma-separated SHA-256 certificate fingerprints for `assetlinks.json`, colon-separated or plain hex, any case (served in uppercase colon form). The built-in default (`config.DefaultAndroidCertFingerprints`: the production upload key and the two staging signers) lets a self-hosted relay open links in the official app with no configuration. Set but empty turns `assetlinks.json` off (404). |
| `RELAY_MAX_COLLECTORS_PER_MAILBOX` | `4` | Concurrent long-polls plus WebSockets per mailbox. |
| `RELAY_MAX_WS_SESSIONS` | `4000` | Open WebSocket collect sessions per relay process, over all mailboxes. An upgrade beyond it is answered `429 rate_limited` with `retry_after` 5; long-poll isn't affected. At about 45 KiB a session the default is about 176 MiB. |
| `RELAY_MAX_WS_SESSIONS_PER_NETWORK` | `1024` | Of those, the sessions of one client network (the IPv4 address or the IPv6 /64) per relay process. The first session of a mailbox is always admitted, so a full network keeps no mailbox behind it from collecting; beyond the maximum a network gets one session per mailbox, up to the ceiling below. Other upgrades are answered `429 rate_limited` with `retry_after` 5. See [Rate limiting](#rate-limiting). |
| `RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD` | `2000` | The most sessions of one client network per relay process, first sessions of mailboxes included: no network passes it, so one network can't take all of a process's sessions. Must be at least `RELAY_MAX_WS_SESSIONS_PER_NETWORK` and at most `RELAY_MAX_WS_SESSIONS` (set all three when lowering one). A vault host with more vaults than this behind one address on one process needs it raised, or its further vaults must collect by long-poll. |
| `RELAY_REPLAY_CACHE_MAX` | `1000000` | Replay-cache capacity. When it's full, requests are shed with `rate_limited` and no live entries are evicted. |
| `RELAY_SWEEP_INTERVAL` | `60s` | TTL sweeper period. The first pass is jittered. |
| `RELAY_SHUTDOWN_TIMEOUT` | `20s` | Bound on the graceful drain after SIGTERM. |

## Rate limiting

Spec §7.2 has the rules, where each number comes from, and what this
version does not protect against. In short:

- An address is not a client. Every vault on a vault host reaches the relay
  from that host's one address, and phones behind a carrier NAT share
  theirs. So an address is a limit's key only while the caller is
  unauthenticated; after that the **key** is limited (`RELAY_RATE_KEY_*`,
  `RELAY_RATE_SENDER_*`).
- Per network there is the **flood guard** (`RELAY_RATE_IP_*`), first,
  before anything is parsed, so it bounds every signature check, replay
  record and store read; the budget of **new mailboxes**
  (`RELAY_RATE_REGISTER_*`); and two **byte budgets**, which bound what one
  network can make the relay store and move however many keys and
  mailboxes it holds: 256 KiB/s (burst 8 MiB) for deposits and claims
  (`RELAY_RATE_IP_BYTES_*`), and for blob uploads and downloads a ceiling
  of 8 MiB/s (burst 256 MiB, `RELAY_RATE_BLOB_BYTES_*`) on top of a budget
  per authenticated key, 1 MiB/s (burst 32 MiB, `RELAY_RATE_BLOB_KEY_BYTES_*`),
  so a vault host's vaults don't share one blob budget (an upload's key
  pays only once its signature has verified). They are charged
  with the declared length before a body is read, never look at the
  target, and are per process. Nothing else keyed on a network can refuse a request
  that is properly signed by a key with a mailbox. There is no penalty
  state.
- A vault host of 900 vaults, at a message a minute each of 4 KB, stores
  about 15 messages a second, about 80 KB/s of deposit bodies (base64
  makes 4 KB about 5.5 KB): about a third of the deposit byte budget. The
  burst holds about 1,500 such deposits at once. A mass unlock is paced
  by the flood guard first (100 requests a second, of which about a third
  are deposits: about 180 KB/s). The byte budget binds a network only
  when it deposits more than about 47 messages of 4 KB a second for
  longer than the burst lasts.
- **Blob transfers**: at most 8 per process, of which at most 6 uploads
  (2 are kept for downloads); per mailbox at most 2 uploads and,
  separately, 2 downloads; one upload at a time per sender key and
  mailbox. An upload takes its slot once its body has begun to arrive,
  and every transfer must keep a pace of 16 KiB per 5 s
  (`RELAY_BLOB_PACE_BYTES`) and finish within 5 minutes, or it is dropped
  and its slot freed: one that trickles at the minimum pace holds its slot
  up to 5 minutes. Refusals are counted as `blob_slots`,
  `blob_mailbox_slots` and `blob_sender_slots`.
- **Refunds.** A deposit or claim charged to a byte budget and then not
  stored gets its charge back, so a sender retrying against a full
  mailbox doesn't drain its network's budget. A blob upload that held a
  transfer slot and stored nothing gets back only what it never sent:
  holding a slot with a trickle always costs the bytes trickled.
- A **WebSocket session** passes these limits once, at its upgrade. After
  that:
  - It has a window of 128 messages sent and not yet acked. The relay
    leases the next batch of 32 only while it fits (so at least 97 are
    outstanding before it pauses), and goes on when acks arrive or the
    leases end. A session that doesn't ack costs at most 128 leases per
    visibility timeout.
  - A session that leaves messages unacked isn't sent the same ones
    ahead of newer ones for ever. Until their first lease ends, the
    window is what holds newer messages back (with 128 unacked there is
    no room). From then on what it was sent before comes again in
    passes: once per visibility timeout a batch, taken before anything
    else when it is due, from the mailbox's oldest message to the newest
    the session had been sent when the pass began; then the next pass.
    New messages (those after the newest it was ever sent) go out the
    rest of the time. A batch is as large as leaves one batch of the
    window free for new messages, and at least 32: 96 when nothing else
    is outstanding (which needs the previous batch to have been written
    out promptly; a slow reader gets a smaller batch, never under 32).
    So neither kind waits for the other: traffic that never pauses can't
    put a due batch off, and new messages wait only for that batch's
    frames, unless the session itself has left more than 64 unacked.
    An unacked message comes again once in every pass, and a pass over n
    collectable messages is at most ceil(n/32) batches. Batches are one
    visibility timeout apart, or up to two for a session that keeps its
    window full of unacked messages: a pass takes at most ceil(n/32)
    visibility timeouts for a session that acks the new messages it
    gets, 2 × ceil(n/32) in the worst case, and ceil(n/96) for a session
    with nothing else outstanding (128 messages: 2 minutes at the
    default 60 s; a full mailbox of 10,000: about 105 minutes), until
    the message is acked or expires. Order across redelivery isn't
    guaranteed. Another session or a long-poll on the same mailbox
    collects those messages oldest first as always. When a whole pass
    finds nothing to send again, the session is back to plain
    oldest-first.
  - An ack frame that names a message in the window is free, once. Every
    other ack frame (a message received elsewhere, an id acked before or
    after its lease ended, an id that names nothing) is charged like
    `DELETE /v1/mailbox/{msg_id}`: a token of the flood guard and one of
    the key's bucket. If either is empty the session is closed with
    **1013** (try again later) and the reason `rate_limited`.
  - A frame that isn't `{"ack":"<msg_id>"}` with a ULID in upper case
    closes the session with **1008**.
  - A process carries at most `RELAY_MAX_WS_SESSIONS` sessions. Of one
    network it carries `RELAY_MAX_WS_SESSIONS_PER_NETWORK` (1,024), and
    beyond that only the first session of a mailbox, up to
    `RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD` (2,000), which nothing
    passes. A vault host is one network and each of its vaults a
    mailbox's first session: the projected 900 fit, with room for sessions
    that overlap while clients reconnect; more than 2,000 vaults behind
    one address on one process don't, until the number is raised: the
    rest must collect by long-poll (a client whose upgrade is answered
    `429` should fall back to it; one that only retries the WebSocket
    stays without a collector). The ceiling is per process, so a host
    can hold 2,000 on each. One address that registers mailboxes as
    fast as the new-mailbox budget allows reaches 1,024 sessions on a
    process in about 4 minutes and 2,000 (about 88 MiB) in about 20, and
    no more: it can't fill a process by itself.
  - Refused upgrades are counted in `relay_ratelimit_refused_total` under
    `ws_sessions` (the process is full), `ws_network` (the network is at
    its maximum and the mailbox has a session) and `ws_network_hard` (the
    network is at its ceiling), and at the end of the `rate limits` line
    as `ws_sessions_refused`, `ws_network_refused` and
    `ws_network_hard_refused`.
- On owner routes the mailbox is looked up before the replay record is
  written, so a signed request under a key without a mailbox writes none.
- A deposit's body is read only after its token has verified (§5.3 steps
  1–6 need only headers). A request refused before its body was read is
  answered at once with `Connection: close`. Small bodies (register,
  rotate, denylist, claim: at most 16 KiB), which are read before the
  signature can be checked, have 10 s to arrive (13 kbit/s).
- No limit is an oracle; there is no allowlist.
- With Valkey the buckets are shared by all relay processes (the web bucket
  and the per-mailbox collector cap are per process). If Valkey is
  unreachable they fall back to per-process ones.

**When to raise the flood guard.** A host's steady traffic reaches the
rate (100/s) at about 2,500 idle vaults, 1,100 at a message a minute each,
700 at two: watch `address_busiest_per_min` in the log line below and
raise the rate at 3,000 (half the guard). The burst (300) lets about 100
vaults unlock, or 300 re-poll, in the same instant; more are refused once
and are back within seconds (500 re-polling: 2.5 s; 900: 7 s). It is also
the size of every instantaneous memory cost, so raise it only if
`address_refused` shows for a known host after deploys or mass unlocks.

Metrics (on the metrics listener; the only label is the limiter's name,
nothing identifies a client): `relay_ratelimit_allowed_total`,
`relay_ratelimit_refused_total`, `relay_ratelimit_peak_permille` (how full
the busiest bucket of each limiter got in the last full minute; 1000 means
something was refused), `relay_ratelimit_busiest_per_minute` (requests of
the busiest single network and of the busiest single key). Limiters:
`address`, `key`, `sender`, `register`, `claim`, `web`, and the byte
budgets `bytes`, `blob_bytes` (per network) and `blob_key_bytes` (per
key) (for these a request allowed or refused is counted, and
`relay_ratelimit_busiest_bytes_per_minute` has the bytes of the busiest
single network, or key); `relay_ratelimit_refused_total` also has
`blob_slots`, `blob_mailbox_slots` and `blob_sender_slots`. Each process logs one `rate limits`
line a minute with the same figures, the number of networks the flood
guard refused, and `collectors`, `parked` and `ws_sessions`: this line is
what the limits are to be re-sized from. After the WebSocket refusals it
ends with `bytes_peak`, `bytes_refused`, `bytes_busiest_per_min`,
`blob_bytes_peak`, `blob_bytes_refused`, `blob_bytes_busiest_per_min`,
`blob_key_bytes_peak`, `blob_key_bytes_refused`,
`blob_key_bytes_busiest_per_min`, `blob_slots_refused`, `blob_mailbox_slots_refused`,
`blob_sender_slots_refused`, `log_dropped` and `log_suppressed`.

The simulation behind the numbers is a test:

```sh
go test ./internal/api -run 'TestLoad|TestUnlockStorm' -v
```

The two-process tests (`TestMultiProcess*`: the flood guard and the
per-key limit shared across processes) need DynamoDB Local and Valkey:
they run under `make test-dynamo` and in CI's `shared-backend` job, and a
plain `go test ./...` skips them on purpose.

It puts 100, 500, 900 and 2,000 vaults behind one address, each behaving as
vettid-vault does (a long-poll every 25 s, an ack and a new collect per
message, a deposit per message sent, and the client's retries on 429),
against the real handler chain with a simulated clock, under a single
bucket of 20/s, burst 40 ("old": this code with `main`'s limits, not
`main`'s code) and under the defaults.

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
- **Logs.** Logs are JSON on stdout, one access line per request (at
  debug level for `429` answers, healthy `/healthz` probes and empty
  collects), within the log budget (`RELAY_LOG_INFO_RPS`; successful
  state-changing requests have a budget of their own). Each line
  has the route *pattern* (never the raw path, which contains ids), status,
  error code, sizes, duration and, where relevant, the `msg_id` or
  `blob_id`. Payloads, blob bytes, tokens, signatures, public keys, mailbox
  ids and client IPs are never logged. A test enforces this. For the web
  endpoints the line has the route (`/connect`,
  `/.well-known/assetlinks.json`, or `unmatched` for every other path),
  never the query, the raw path or `Referer`.
- **Web endpoints** (spec §6.11). `/connect`, `/.well-known/assetlinks.json`
  and `/robots.txt` are fixed documents built at startup (the page is
  embedded with `go:embed` from `internal/api/web/`), the same bytes for
  every request: query ignored, `GET`/`HEAD` only (`405` otherwise),
  `Cache-Control: public, max-age=86400, immutable` with a strong `ETag`.
  The page's CSP allows its one inline style and script by SHA-256 hash,
  computed from the embedded page at startup and checked by a test, so
  editing `connect.html` needs no hash bookkeeping. Exact paths only: any
  other spelling is the ordinary `404`, and the relay never redirects
  (non-canonical paths are `404` everywhere). `Strict-Transport-Security`
  is sent when `RELAY_BASE_URL` is `https`, including behind a
  TLS-terminating proxy.

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
- **Blob bodies** are S3 objects `blobs/<mailbox>/<blob id>`; metadata (size
  and expiry; not the sender) and the storage quota are in DynamoDB. Give the bucket a lifecycle rule that
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
  `RELAY_MAX_WS_SESSIONS`, `RELAY_MAX_WS_SESSIONS_PER_NETWORK`,
  `RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD`,
  `RELAY_MAX_CONCURRENT_BLOB_TRANSFERS`,
  `RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX`, the two byte budgets
  (`RELAY_RATE_IP_BYTES_*`, `RELAY_RATE_BLOB_KEY_BYTES_*`,
  `RELAY_RATE_BLOB_BYTES_*`), the log budget and
  the replay-cache capacity bound each process's own resources. With N
  processes behind a load balancer a network's byte budgets are up to N
  times the configured ones. A client that reconnects to another
  process is counted there afresh.
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
  SQLite does with foreign keys), leaving a tombstone like a deletion's,
  and tombstones when they expire. Purges are idempotent.
- **Mailbox deletion** (§6.10). One transaction marks the mailbox item
  deleted and the counters item dead (and records the tokens-not-before
  time on both); from then on every deposit, blob upload, claim creation
  and denylist write on any process fails its transaction condition, even
  where that process still has the mailbox cached. The process that took
  the request then deletes the partition's contents (blob bodies and the
  mailbox's claims included), bumps the mailbox's empty-hint version and
  publishes a deletion signal on the wake bus: other processes drop the
  mailbox from their cache and end its parked collectors at once (a lost
  signal only delays this until the cache entry expires, ≤ 5 min; their
  collects then see an empty mailbox). The two tombstone items are purged
  by the sweeper when the tombstone expires. Rotation adds the old id to
  the successor's `preds` so a deletion can follow the chain.

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
| `DELETE /v1/mailbox` | owner, no body | always `204` (idempotent): the mailbox, its contents and rotated predecessors are deleted |
| `PUT /v1/blob/{mailbox_id}` | deposit token + signed by `sub` | `201 {blob_id, expires_at}` |
| `GET /v1/blob/{blob_id}` | owner of the recipient mailbox | `200 application/octet-stream` |
| `DELETE /v1/blob/{blob_id}` | owner | `204` (idempotent) |
| `PUT /v1/claim` | signed by a registered mailbox key | `201 {claim_id, expires_at}` |
| `GET /v1/claim/{claim_id}` | none (rate-limited) | `200 application/octet-stream`. Single fetch: the claim is deleted. |
| `DELETE /v1/claim/{claim_id}` | the creating key | `204` (idempotent) |
| `GET /healthz` | none | `200` when the DB is reachable and not draining, else `503`. The DB is asked at most once every 2 s per process; requests in between get the last answer |
| `GET /connect` | none (web bucket) | `200 text/html`: the invitation landing page (§6.11). Invitation URLs are `<relay>/connect#<link>`; the fragment never reaches the relay. |
| `GET /.well-known/assetlinks.json` | none (web bucket) | `200 application/json`: Android App Links statement for the VettID app |
| `GET /robots.txt` | none (web bucket) | `200 text/plain` |

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
  verification, and the per-network flood guard applies before any header,
  token or body parsing. Deposits follow §5.3 exactly, and like blob
  uploads run steps 1–6 on headers alone, so unauthorized deposits and
  uploads are refused before their body is read (with `Connection:
  close`); the body is then read with the limit enforced while reading.
  Per-key limits apply only after authentication.
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
- **Deletion tombstones** (§6.10) keep the mailbox id, the
  tokens-not-before time (deletion + 90 s) and an expiry of that time plus
  the denylist retention. With SQLite they are a table without a foreign
  key to the mailbox; with DynamoDB, the mailbox and counters items.
- **Rotated-away mailboxes leave tombstones** (§6.7): the sweeper (or a
  re-registration of the old key, whichever removes the mailbox first)
  writes the deletion tombstone with the removal time, so tokens issued
  under the old registration stay refused. Registering a key past its
  rotation grace starts a fresh, empty mailbox (`201`). (Before 0.5.0 it
  answered `200` for a mailbox that no longer resolved, and a swept
  mailbox's key could register again with its old tokens valid.)
- **Open tokens and blobs.** One-shot open tokens are refused for
  `PUT /v1/blob` with `token_invalid`. §5.6 grants "exactly one deposit".
  §6.8 says blob authorization is "identical to deposit", but letting a
  bearer token upload a large blob is not needed for first contact, so the
  relay refuses it.
- **Open tokens and rate limits.** For open tokens, the per-sender rate
  bucket is keyed by the token's `jti`: an open token has no fixed sender
  and is single-use.
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
the other process, shared rate limits (the flood guard, the per-key limit,
claim fetches), and a process stopping mid-test.

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
