# Freebird — a microblog on Freenet

2026-08-09. Status: implemented, **amended** by
`2026-08-10-anonymous-parity.md` — that spec replaced the ghostkey write gate
described here with a two-tier slot policy. Where the two disagree, it wins.

Twitter-like microblogging built entirely on Freenet: no server, per-author
feed contracts, per-author reply inboxes, client-side aggregation. Signup is
anonymous; a Ghost Key buys a verified check mark and durable slots on shared
surfaces.

## Trust model (one rule)

**Everyone writes; a Ghost Key buys durability.** Anyone can post to their
own feed with a locally generated key, and anyone can write to the
shared-write surfaces — reply inboxes and the directory now; town square,
mentions later. Those surfaces cap anonymous and attested writers in separate
tiers: under load anonymous writers are evicted first, attested writers are
never crowded out by them.

## Goals (MVP)

- Anonymous signup: delegate generates an Ed25519 posting keypair locally;
  no prompt, no network.
- Post short messages (~1–2 KB) to your own feed.
- Follow authors by key/address; home feed merges their feeds client-side.
- Replies: content lives in the replier's feed (`in_reply_to`); discovery
  via a per-author reply inbox contract (open writes, two-tier slot policy).
- Check mark: optional Ghost Key attestation on a feed, verified by the
  contract, rendered by the UI.
- Public follow list.

Out of scope for MVP: global discovery/firehose, mentions/notifications
(the inbox contract will double for mentions later), likes/reposts, media,
private follows.

## Architecture

### No server

The Freenet node is the server. UI ships as a webapp container contract
(`fdev` website flow), published from the explorer node. All multi-contract
logic (feed aggregation, thread resolution) runs client-side — the platform
forbids contract-to-contract calls.

Deferred: a doorbell-style keeper daemon renewing subscriptions for popular
feeds (subscriptions are ~2-minute leases; unwatched contracts rot). The
existing doorbell pattern (freenet-metrics reference impl) drops in when
needed.

### Feed contract (one per author)

- **Params**: author's Ed25519 posting verifying key + Freenet ghostkey
  master verifying key (trust anchor). Address = hash(wasm, params) →
  deterministic; anyone knowing your key can compute your feed address.
- **State** (CBOR): profile (display name, bio), public follow list,
  `attestation: Option<GhostkeyAttestation>`, capped ring of signed posts.
- **Caps**: ~200–500 posts, ~1–2 KB per post; total state well under 1 MB
  (measured practical PUT limit; failure rate climbs steeply past ~2 MB).
- **Merge**: dedupe by post id, sort by `(time, id)`, truncate to cap.
  Attestation merge: valid beats none; two valid tie-break by max cert hash.
- **Validation**: every post signed by the posting key. If an attestation is
  present: verify chain Master → Notary → Ghost Key and that it signs this
  contract's posting key; invalid attestation ⇒ state rejected network-wide,
  so readers' UIs trust the flag without re-verifying. Absent attestation is
  valid (unbadged).
- **Upgrade path**: an anonymous account adds an attestation later via a
  state update; same key, so address, followers, and history survive.

### Reply inbox contract (one per author)

Reply *content* is a post in the replier's own feed carrying `in_reply_to`
(author key + post id). The inbox makes replies discoverable:

- **Params**: same shape as the feed (author posting key + master key);
  different wasm ⇒ different, still-computable address.
- **State**: a fingerprint-keyed credential map (posting key + attestation,
  ~1 KB each — the RSA notary layer makes certs heavy, so each replier's
  cred is stored once) plus a capped ring of signed reply pointers (replier
  fingerprint, target post id, reply id, timestamp). Caps: 300 pointers
  globally, 8 per ghost-key fingerprint (bounds what one purchase can
  occupy); cleanup prunes creds no pointer references.
- **Writes are open to everyone** (amended: v1 required a valid Ghost Key
  cert chained to the master key). Anonymous and attested repliers hold
  separate slot tiers; see `2026-08-10-anonymous-parity.md` for the caps,
  fingerprints, and eviction order that superseded the caps above.
- **Open-write hardening** (doorbell lessons): reject far-future timestamps
  in validate, clamp before merge, retention horizon, plus a per-replier cap
  so one ghostkey holder cannot evict everyone else's pointers.
- Thread rendering: fetch author feed + author inbox → resolve pointers into
  repliers' feeds.
- Later reuse: same contract doubles as the mentions inbox.

### Lessons copied from River (not re-derived)

1. **Retention horizon** on every capped log (River
   `common/src/room_state/message.rs`, `RetentionHorizon`). A capped log
   without it livelocks peers re-offering pruned entries — caused a real
   incident (one room = 63.7% of network broadcast work, 2026-07-25).
2. **Byte-canonical summaries** — `BTreeSet` never `HashSet`
   (freenet-core#4857); freenet-core byte-compares summaries.
3. **CRDT logic in a plain library crate** (`freebird-core`), contracts as
   thin (~200-line) shells. Port River's convergence / summary-determinism /
   retention proptests conceptually.

### Delegates

- **Freebird KV delegate** (pattern-copy of River's chat-delegate):
  generates and stores the posting key, drafts, local caches. Encrypted at
  rest, per-origin partitioned. Posts and reply pointers are signed locally
  — no per-message delegate round-trip (River's lag lesson, river#512).
- **Ghostkey delegate** (existing, deployed as the Identity Vault): used
  only when the user opts into verification — signs the attestation binding
  their posting key to their ghost key. One permission prompt, once.
- Gotcha (freenet/ghostkeys#21): never hardcode the ghostkey delegate key in
  contracts/app constants — re-keying breaks apps. Keep it in config.
- V2 delegate contract ops (PUT/UPDATE) are local-only and bypass
  validate_state — never use them to publish.

### UI

Dioxus/Rust → wasm (River's stack). Reuses `freebird-core` types directly;
copy River's `connection_manager` / `room_synchronizer` / watchdog patterns.
Connects to the node via `freenet_stdlib::client_api::WebApi` over the
node's WebSocket command endpoint. Home feed = subscribe to each followed
feed contract, merge locally. Check mark rendered from the verified
attestation (optionally with tier / ghostkey fingerprint).

## Repo layout

```
common/          freebird-core: types, CRDT merge, ghostkey chain verification, proptests
contracts/feed-contract/
contracts/inbox-contract/
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
  summary determinism, retention-horizon no-livelock, inbox per-replier-cap
  eviction fairness.
- Local loopback test network (existing brain runbook) for end-to-end:
  publish feed from node A, subscribe/read/reply from node B.

## Sequencing

1. `freebird-core`: post/feed/inbox types, merges, proptests. (No ghostkey
   dependency yet.)
2. Feed contract shell; validate on local test network.
3. KV delegate (keygen + storage) + Dioxus UI skeleton: post, follow, home
   feed. **Anonymous-only Freebird works end-to-end here.**
4. Ghostkey integration: clone `freenet/ghostkeys`, confirm the cert
   format + verification crate compiles to wasm (fallback: vendor the
   ed25519 chain-check). Attestation in feed contract + check mark in UI +
   Identity Vault signing flow.
5. Inbox contract (needs 4) + thread rendering.
6. Webapp container; publish from the explorer node.

## Decisions log

- Branding: a post is a **Peep**; reposts (**Repeeps**) are post-MVP; Replies,
  Feeds, Followers keep their usual names. Wire/type names stay `Post*`.
- Implemented caps: 300 peeps/feed, 2 KB/peep, 300 inbox pointers, 8 per
  fingerprint, 10-minute future-timestamp tolerance.
- ghostkey_lib 0.2.0 is used directly in contract wasm (proven clean: only
  freenet host imports; `getrandom` "custom" stub defuses river#241).

- Signup: anonymous, local keygen in delegate. Ghost Key NOT required to post.
- Ghost Key = check mark (optional feed attestation) + a durable, uncrowdable
  slot tier on shared-write surfaces. (Amended: v1 made it *required* for
  those surfaces; the two-tier policy replaced that gate.)
- Reply discovery (inbox contract) is in the MVP.
- UI stack: Dioxus/Rust (shared types with core; River-proven patterns).
- Follow list: public, in feed contract state.
- Discovery: none in MVP; follow by shared key/address link.
