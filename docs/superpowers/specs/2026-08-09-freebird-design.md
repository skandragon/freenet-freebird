# Freebird — a microblog on Freenet

2026-08-09. Status: approved design, pre-implementation.

Twitter-like microblogging built entirely on Freenet: no server, per-author
feed contracts, client-side aggregation, Ghost Key–gated posting.

## Goals (MVP)

- Post short messages (~1–2 KB) to your own feed.
- Follow other authors by key/address; home feed merges their posts client-side.
- Replies via `in_reply_to` references.
- Posting requires a Ghost Key (paid, donation-backed credential) — sybil
  resistance from day one.
- Public follow list (enables counts/discovery later).

Out of scope for MVP: global discovery/firehose, mentions/notifications
(needs an open-write inbox contract with doorbell hardening), likes/reposts,
media, private follows.

## Architecture

### No server

The Freenet node is the server. UI ships as a webapp container contract
(`fdev` website flow), published from the explorer node. All multi-contract
logic (feed aggregation, reply resolution) runs client-side — the platform
forbids contract-to-contract calls.

Deferred: a doorbell-style keeper daemon renewing subscriptions for popular
feeds (subscriptions are ~2-minute leases; unwatched contracts rot). The
existing doorbell pattern (freenet-metrics reference impl) drops in when
needed.

### Feed contract (one per author)

- **Params**: author's Ed25519 posting verifying key + Freenet ghostkey
  master verifying key (trust anchor). Address = hash(wasm, params) →
  deterministic; anyone knowing your key can compute your feed address.
- **State** (CBOR): profile (display name, bio), public follow list
  (set of author keys), authorship certificate (see below), capped ring of
  signed posts.
- **Caps**: ~200–500 posts, ~1–2 KB per post; total state well under 1 MB
  (measured practical PUT limit; failure rate climbs steeply past ~2 MB).
- **Merge**: dedupe by post id, sort by `(time, id)`, truncate to cap.
  Single-author, so no member tree — much simpler than River's room.
- **Validation**: cert chain Master → Notary → Ghost Key → authorship cert →
  posting key, then per-post signature under the posting key. Pure ed25519,
  wasm-compatible.

Lessons copied from River (not re-derived):

1. **Retention horizon** on the capped post log (River
   `common/src/room_state/message.rs`, `RetentionHorizon`). A capped log
   without it livelocks peers re-offering pruned entries — caused a real
   incident (one room = 63.7% of network broadcast work, 2026-07-25).
2. **Byte-canonical summaries** — `BTreeSet` never `HashSet`
   (freenet-core#4857); freenet-core byte-compares summaries.
3. **CRDT logic in a plain library crate** (`freebird-core`), contract as a
   thin (~200-line) shell. Port River's convergence / summary-determinism /
   retention proptests conceptually.

### Delegates

- **Ghostkey delegate** (existing, deployed as the Identity Vault): signs an
  **authorship certificate** once, binding a locally generated Ed25519
  posting key to the user's ghost key. One permission prompt at account
  creation. Posts are then signed locally — avoids River's per-message
  delegate round-trip lag (river#512).
- **Freebird KV delegate** (pattern-copy of River's chat-delegate): stores
  posting key, drafts, local caches. Encrypted at rest, per-origin
  partitioned.
- Gotcha (freenet/ghostkeys#21): never hardcode the ghostkey delegate key in
  contracts/app constants — re-keying breaks apps. Keep it in config.
- V2 delegate contract ops (PUT/UPDATE) are local-only and bypass
  validate_state — never use them to publish posts.

### UI

Dioxus/Rust → wasm (River's stack). Reuses `freebird-core` types directly;
copy River's `connection_manager` / `room_synchronizer` / watchdog patterns.
Connects to the node via `freenet_stdlib::client_api::WebApi` over the
node's WebSocket command endpoint. Home feed = subscribe to each followed
feed contract, merge locally.

## Repo layout

```
common/          freebird-core: types, CRDT merge, cert-chain verification, proptests
contracts/feed-contract/
delegates/freebird-delegate/
ui/              Dioxus web app
```

## Error handling / correctness

- Deltas must be commutative (platform requirement; non-compliant contracts
  get deprioritized network-wide).
- Cleanup/merge must be idempotent (`f(f(s)) == f(s)`); Freenet runs it a
  variable number of times per peer.
- PUT retries with backoff + verify-by-GET (PUTs fail ~14% even at 1 MB).
- Reject far-future timestamps in validate (doorbell hardening lesson).

## Testing

- Proptests in `freebird-core`: convergence (merge order-independence),
  summary determinism, retention-horizon no-livelock.
- Local loopback test network (existing brain runbook) for end-to-end:
  publish feed from node A, subscribe/read from node B.

## Sequencing

1. Clone `freenet/ghostkeys`; confirm cert format + verification crate is
   reusable as a wasm dependency. (Risk item — if not reusable, vendor the
   verification math.)
2. `freebird-core`: post/feed types, merge, verification, proptests.
3. Feed contract shell; validate on local test network.
4. KV delegate + ghostkey authorship-cert flow.
5. Dioxus UI + webapp container; publish from the explorer node.

## Decisions log

- UI stack: Dioxus/Rust (shared types with core; River-proven patterns).
- Follow list: public, in feed contract state.
- Discovery: none in MVP; follow by shared key/address link.
- Ghostkey required to post: yes, from MVP.
