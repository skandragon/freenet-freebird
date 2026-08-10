# Freebird MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Twitter-like microblog on Freenet: per-author feed contracts, per-author reply inboxes, anonymous signup, Ghost Key check marks, Dioxus UI. Spec: `docs/superpowers/specs/2026-08-09-freebird-design.md`.

**Architecture:** Cargo workspace modeled on River (`~/git/github/freenet/river`): CRDT logic in `common/` (crate `freebird-core`) using freenet-scaffold `#[composable]`, contracts as thin shells, a KV delegate, Dioxus 0.7 UI. Ghostkey verification reuses the `ghostkey_lib` crate (chain: master Ed25519 → notary RSA blind-sig → ghost Ed25519).

**Tech Stack:** Rust 2021, freenet-stdlib 0.8.5, freenet-scaffold 0.2.2, ghostkey_lib 0.2.0, ciborium, ed25519-dalek 2.1.1, Dioxus 0.7, proptest.

## Global Constraints

- License: AGPL-3.0-or-later. Repo public at github.com/skandragon/freenet-freebird.
- **wasm dep hygiene (river#241):** contract + delegate crates must never pull `rand`/`getrandom` with default backends. ghostkey_lib pulls `rand` unconditionally, so every crate that compiles it to wasm32 adds `getrandom = { version = "0.2", features = ["custom"] }` and never registers a custom backend (verification paths call no RNG). No `wasm-bindgen` imports may appear in contract/delegate wasm.
- **Summaries byte-canonical:** `BTreeMap`/`BTreeSet` only in any type reaching a summary (freenet-core#4857).
- **Merges commutative + idempotent:** `apply_delta` order-independent; `post_apply_cleanup(s) == post_apply_cleanup(post_apply_cleanup(s))`.
- **Capped logs need retention horizons** (River incident 2026-07-25): peers publish the oldest key they retain; senders offer only strictly newer.
- State caps: posts ≤ 2 KB each / 300 per feed; inbox ≤ 300 pointers, ≤ 8 per ghost fingerprint. Total state ≪ 1 MB.
- Wire format: CBOR via ciborium everywhere.
- Timestamps: `u64` millis; validate/merge reject entries > 10 min in the future (clamp OUTSIDE the pure merge — doorbell hardening).
- Trust anchor: ghostkey_lib's compiled-in `FREENET_MASTER_VERIFYING_KEY_BASE64`; every verify fn takes `master_override: Option<&VerifyingKey>` (None in contracts, Some in tests). Contract params carry the author key ONLY.
- Attestation domain tag: `b"freebird:attest:v1:"` + 32-byte posting verifying key = the payload the ghost key signs (inside ghostkeys' `ScopedPayload`).
- Commit after every green test cycle; short commit messages.

---

### Task 1: Workspace scaffold + public repo

**Files:**
- Create: `Cargo.toml` (workspace), `LICENSE` (AGPL-3.0-or-later text), `README.md`, `.gitignore`, `rust-toolchain.toml`, `common/Cargo.toml`, `common/src/lib.rs` (empty modules)

Workspace copies River's profile setup (`opt-level='z'`, lto, panic=abort for release; `wasm-release` profile for dx) and dependency-hygiene comments. Members: `common`, `contracts/feed-contract`, `contracts/inbox-contract`, `delegates/freebird-delegate`, `ui` (members added as tasks create them; start with `common`).

- [ ] Write workspace `Cargo.toml` with `[workspace.dependencies]`: ciborium 0.2.2, serde 1 (derive), ed25519-dalek 2.1.1 (default-features=false, alloc+serde), blake3 1.5, bs58 0.5, ghostkey_lib 0.2.0, getrandom 0.2 (no features at workspace level), freenet-stdlib 0.8.5 (contract), freenet-scaffold 0.2.2, freenet-scaffold-macro 0.2.2, data-encoding 2, base64 0.22, proptest 1 (dev)
- [ ] `curl` the AGPL-3.0 text from gnu.org into LICENSE; README: one-paragraph description + spec pointer
- [ ] `cargo check -p freebird-core` passes (empty lib)
- [ ] `gh repo create skandragon/freenet-freebird --public --source=. --push -d "Microblogging on Freenet"`
- [ ] Commit + push

### Task 2: freebird-core types + attestation verification

**Files:**
- Create: `common/src/types.rs`, `common/src/attestation.rs`, `common/src/lib.rs` (pub mods + cbor helpers), `common/tests/attestation.rs`

**Produces (later tasks consume):**
```rust
pub fn to_cbor<T: Serialize>(v: &T) -> Result<Vec<u8>, String>;
pub fn from_cbor<T: DeserializeOwned>(b: &[u8]) -> Result<T, String>;
pub struct PostId(pub [u8; 16]);                     // blake3(author_vk ‖ time ‖ content)[..16]
pub struct PostV1 { pub id: PostId, pub time: u64, pub content: String,
                    pub in_reply_to: Option<PostRef> }
pub struct PostRef { pub author: VerifyingKey, pub post: PostId }
pub struct AuthorizedPost { pub post: PostV1, pub signature: Signature } // sig over to_cbor(post)
pub struct ProfileV1 { pub name: String, pub bio: String, pub version: u32 }
pub struct AuthorizedProfile { pub profile: ProfileV1, pub signature: Signature }
pub struct FollowsV1 { pub follows: BTreeSet<[u8;32]>, pub version: u32 }
pub struct AuthorizedFollows { pub follows: FollowsV1, pub signature: Signature }
pub struct AttestationV1 { pub scoped_payload: Vec<u8>, pub signature: Signature,
                           pub certificate: GhostkeyCertificateV1 }
impl AttestationV1 {
  /// Full chain check; returns notary tier info string on success.
  pub fn verify(&self, posting_key: &VerifyingKey,
                master_override: Option<&VerifyingKey>) -> Result<String, String>;
  pub fn fingerprint(&self) -> String;  // ghostkeys' blake3[..8] bs58 fingerprint
  pub const DOMAIN: &[u8] = b"freebird:attest:v1:";
}
/// Test helper (cfg(any(test, feature = "test-fixtures"))): mint a full chain.
pub fn test_chain(posting_key: &VerifyingKey)
  -> (AttestationV1, VerifyingKey /* master */);
```
`verify` steps: (1) `certificate.verify(&master_override.cloned())` — notary + RSA layers; (2) ed25519-verify `signature` over `scoped_payload` bytes with `certificate.verifying_key`; (3) CBOR-decode `ScopedPayload { requestor, payload }` (mirror ghostkeys' shape locally — requestor decoded as `ciborium::Value`, not pinned); (4) require `payload == DOMAIN ‖ posting_key.as_bytes()`.

- [ ] Write failing tests: `valid_chain_verifies_and_returns_tier`, `wrong_master_rejected`, `tampered_payload_rejected`, `attestation_for_different_posting_key_rejected`, `post_signature_roundtrip`
- [ ] Run `cargo test -p freebird-core` — expect compile failure / red
- [ ] Implement types.rs + attestation.rs (test_chain mints master + notary via `NotaryCertificateV1::new`, ghost cert via `GhostkeyCertificateV1::new`, signs `ScopedPayload{requestor: Delegate-ish placeholder, payload: DOMAIN‖vk}` with ghost signing key)
- [ ] Green; commit

### Task 3: Feed state CRDT

**Files:**
- Create: `common/src/feed.rs`, `common/tests/feed_convergence.rs`

**Produces:**
```rust
pub struct FeedParametersV1 { pub author: VerifyingKey }
#[composable(post_apply_delta = "post_apply_cleanup")]   // field order load-bearing
pub struct FeedStateV1 {
  pub profile: ProfileComponent,       // LWW by (version, sig-valid); owner-signed
  pub follows: FollowsComponent,       // LWW by version; owner-signed
  pub attestation: AttestationComponent, // Option; valid-beats-none; tie: max blake3(cert bytes)
  pub posts: PostsComponent,           // capped log
}
pub const MAX_POSTS: usize = 300;
pub const MAX_POST_BYTES: usize = 2048;
pub const MAX_FUTURE_MS: u64 = 600_000;
```
Each component implements freenet-scaffold `ComposableState` (copy River `common/src/room_state/*.rs` shapes). PostsComponent: `Vec<AuthorizedPost>`; summary = `{ ids: BTreeSet<PostId>, horizon: RetentionHorizon }` where `RetentionHorizon::{Open, OldestRetained((u64, PostId)), Closed}` ports River `message.rs:52-115` semantics; delta = posts newer than the peer's horizon and not in their id set. `apply_delta`: verify sig under `params.author`, drop > MAX_POST_BYTES, drop id-dupes, sort `(time, id)`, truncate oldest beyond MAX_POSTS. Future-timestamp clamp happens in `verify` (validate path) and pre-merge scrub in `post_apply_cleanup` — never inside the pure fold. Attestation verification inside `verify` uses `master_override: None` under `#[cfg(target_arch = "wasm32")]`-independent runtime flag: params stay author-only, tests construct states via a `verify_with_master` helper.

- [ ] Failing tests first: unit (`post_cap_evicts_oldest`, `bad_signature_rejected`, `future_post_rejected_in_verify`, `oversize_post_dropped`, `attestation_valid_beats_none`, `attestation_tie_deterministic`) + proptests (`merge_commutative` — any permutation of deltas converges byte-identically, `cleanup_idempotent`, `summary_deterministic` — two structurally-equal states summarize byte-identically, `horizon_no_relivelock` — peer with pruned window produces empty delta against newer horizon)
- [ ] Red → implement → green (`cargo test -p freebird-core`)
- [ ] Commit

### Task 4: feed-contract shell + wasm gate

**Files:**
- Create: `contracts/feed-contract/Cargo.toml`, `contracts/feed-contract/src/lib.rs`

Model: River `contracts/room-contract/src/lib.rs` — `#[contract]` impl deserializing CBOR state/params and delegating to `FeedStateV1`'s ComposableState. Cargo.toml: crate-type cdylib+rlib, deps freebird-core, freenet-stdlib(contract), freenet-scaffold, ciborium, ed25519-dalek, **`getrandom = { workspace = true, features = ["custom"] }`**, and River's do-not-add-rand comment.

- [ ] Implement shell (validate_state / update_state / summarize_state / get_state_delta)
- [ ] `rustup target add wasm32-unknown-unknown` if absent; `cargo build -p feed-contract --target wasm32-unknown-unknown --release`
- [ ] **Gate:** inspect imports — `wasm-tools print target/wasm32-unknown-unknown/release/feed_contract.wasm | grep -c '(import' ` must show only freenet host imports, no `wbg`/wasm-bindgen. (If wasm-tools absent: `cargo install wasm-tools` or check on explorer.) This is the ghostkey_lib-in-wasm risk gate — fail here ⇒ vendor verification math into freebird-core instead (drop ghostkey_lib dep from wasm builds behind a feature)
- [ ] Also compile-check on explorer: `ssh explorer@10.46.101.1` clone repo, same build
- [ ] Commit

### Task 5: Inbox state CRDT + contract

**Files:**
- Create: `common/src/inbox.rs`, `common/tests/inbox_convergence.rs`, `contracts/inbox-contract/{Cargo.toml,src/lib.rs}`

**Produces:**
```rust
pub struct InboxParametersV1 { pub owner: VerifyingKey }
#[composable(post_apply_delta = "post_apply_cleanup")]
pub struct InboxStateV1 {
  pub creds: CredsComponent,      // BTreeMap<String /*fingerprint*/, ReplierCred>
  pub pointers: PointersComponent // capped log of ReplyPointer
}
pub struct ReplierCred { pub posting_key: VerifyingKey, pub attestation: AttestationV1 }
pub struct ReplyPointer { pub fingerprint: String, pub target_post: PostId,
                          pub reply_post: PostId, pub time: u64 }
pub struct AuthorizedReplyPointer { pub ptr: ReplyPointer, pub signature: Signature } // by replier posting key
pub const MAX_POINTERS: usize = 300;
pub const MAX_PER_FINGERPRINT: usize = 8;
```
Validation: pointer's fingerprint must exist in creds; cred's attestation verifies for its posting_key (ghostkey-gated writes); pointer sig verifies under that posting key. Merge: creds union (deterministic — a fingerprint maps to the cred whose CBOR bytes hash lowest, though in practice identical); pointers dedupe by `(fingerprint, reply_post)`, sort `(time, reply_post)`, enforce MAX_PER_FINGERPRINT (keep newest per fingerprint) then MAX_POINTERS. `post_apply_cleanup`: drop creds with zero surviving pointers, drop future-dated pointers. Retention horizon identical in shape to posts.

- [ ] Failing tests: `unattested_pointer_rejected`, `pointer_without_cred_rejected`, `per_fingerprint_cap_keeps_newest_and_cannot_evict_others`, `orphan_creds_pruned`, proptests `merge_commutative`, `cleanup_idempotent`, `summary_deterministic`
- [ ] Red → implement → green
- [ ] Contract shell (same pattern/hygiene as Task 4) + wasm32 build + import check
- [ ] Commit

### Task 6: freebird-delegate (KV store)

**Files:**
- Create: `delegates/freebird-delegate/{Cargo.toml,src/lib.rs}`, `common/src/delegate_api.rs`

Pattern-copy River `delegates/chat-delegate/` minus ecies: per-origin-contract key-value store over `DelegateCtx` secrets (`set_secret`/`get_secret`/`list_secrets` with origin-prefixed keys).

**Produces (in delegate_api.rs, shared with UI):**
```rust
pub enum FreebirdDelegateRequest { Store { key: String, value: Vec<u8> },
  Get { key: String }, Delete { key: String }, List }
pub enum FreebirdDelegateResponse { Stored { key: String },
  Value { key: String, value: Option<Vec<u8>> }, Deleted { key: String },
  KeyList { keys: Vec<String> }, Error { message: String } }
```
Well-known keys (UI convention, doc comment): `posting_key` (32-byte ed25519 seed), `follows_cache`, `draft`. Origin scoping: prefix every secret key with bs58 of the attested `MessageOrigin` contract id; requests from unattested origins get `Error`.

- [ ] Failing tests (native, mock DelegateCtx as chat-delegate's tests do): `store_get_roundtrip`, `origin_isolation`, `list_scoped_to_origin`, `delete_removes`
- [ ] Red → implement → green; wasm32 build + import check (no rand — this crate does NOT touch ghostkey_lib)
- [ ] Commit

### Task 7: UI — connection + sync layer

**Files:**
- Create: `ui/Cargo.toml`, `ui/src/main.rs`, `ui/src/api/{mod,connection,feed_sync,delegate,ghostkey}.rs`, `ui/assets/` (index.html shell per dx convention)

Dioxus 0.7 web. Copy River's shapes: `connection_manager.rs` (WebApi over web_sys WebSocket, `?authToken=` param, reload on AUTH_TOKEN_INVALID), a slimmed synchronizer holding `Signal<BTreeMap<[u8;32], FeedView>>`:

```rust
pub struct FeedView { pub params: FeedParametersV1, pub state: FeedStateV1,
                      pub inbox: Option<InboxStateV1> }
pub async fn subscribe_feed(author: [u8;32]);   // GET+subscribe feed & inbox contracts, merge updates via ComposableState::merge
pub async fn publish_post(post: PostV1);        // sign w/ posting key, Update delta to own feed
pub async fn publish_profile(p: ProfileV1);
pub async fn publish_follows(f: FollowsV1);
pub async fn send_reply_pointer(target_author: [u8;32], ptr: ReplyPointer);
pub fn own_feed_key() -> ContractKey;           // ContractKey from (feed wasm hash, params)
```
`api/delegate.rs`: CBOR round-trip to freebird-delegate over `DelegateOp`. `api/ghostkey.rs`: `RequestAnyAccess` → `SignMessage{message: DOMAIN‖posting_vk}` → build `AttestationV1` from `SignResult` (parse certificate_pem via ghostkey_lib `Armorable::from_armored_string`); ghostkey delegate key is a Settings value (default the deployed vault delegate; NEVER a compile-time constant — ghostkeys#21).

- [ ] `dx build` (or `cargo check -p freebird-ui --target wasm32-unknown-unknown`) compiles
- [ ] Native unit tests for pure logic (contract-key derivation, delta building): `cargo test -p freebird-ui`
- [ ] Commit

### Task 8: UI — screens

**Files:**
- Create: `ui/src/components/{app,onboarding,compose,home_feed,post_card,profile,thread,follows,verify,settings}.rs`

Screens (Dioxus components, minimal styling, one `main.css`):
- **onboarding**: no `posting_key` in delegate → generate ed25519 keypair in browser (getrandom js is fine here), store seed via delegate, PUT initial feed + inbox contracts.
- **home_feed**: merged timeline (own + followed feeds' posts, sort desc `(time, id)`), post_card shows name, check-mark badge when `state.attestation` present (contract-validated ⇒ trust it), fingerprint tooltip.
- **compose**: ≤ 2 KB guard, publishes via `publish_post`; when replying also `send_reply_pointer` (silently skipped if unverified — show "replies from unverified accounts are only visible to followers" hint).
- **thread**: target post + inbox pointers resolved via `subscribe_feed` of each replier.
- **profile** (own: edit name/bio; other: follow/unfollow button → `publish_follows`).
- **verify**: drive `api/ghostkey.rs` flow; on success `publish attestation` update; error path when `NoIdentityAvailable` → link to freenet.org/ghostkey.
- **settings**: node WS URL, ghostkey delegate key.

- [ ] Implement; `dx build --release` green
- [ ] `dx serve` against local node; manual smoke: onboard → post → see own post (verify with browser via playwright if node available; otherwise defer to Task 9 network test)
- [ ] Commit

### Task 9: Packaging, publish tooling, e2e

**Files:**
- Create: `Makefile` (or `Makefile.toml` if cargo-make preferred — plain Makefile), `freenet.toml` webapp packaging config, `scripts/publish.sh`

- [ ] Targets: `make contracts` (both wasm + import check), `make delegate`, `make ui` (dx build --profile wasm-release), `make test` (workspace), `make publish` (fdev flow from explorer per freenet-metrics publish-tooling notes)
- [ ] Local test network e2e (brain runbook `local-test-network`): node A publishes a feed + post, node B computes address from author key, GETs, sees post; reply pointer round-trip with test master key — as `tests/e2e.rs` behind `integration-test` feature, manual-run documented in README
- [ ] Explorer full-workspace compile check over ssh
- [ ] README: build, run, publish, architecture pointer
- [ ] Commit + push

### Task 10: Spec sync + review

- [ ] Update spec Decisions log: params carry author key only (master key compiled in); inbox creds map + per-fingerprint cap 8/300; reply pointers require attested (check-marked) replier
- [ ] Run pr-review-toolkit:code-reviewer over the workspace; fix findings
- [ ] Final push

## Self-review notes

- Spec coverage: feed contract (T3/4), inbox (T5), delegate (T6), anonymous signup (T8 onboarding), attestation/check mark (T2/T8 verify), no server (T9 publish only), caps/horizon/canonical summaries (T3/5), doorbell hardening (T3/5 future-clamp), UI (T7/8). Town square / mentions: out of scope per spec.
- Risk gate order: ghostkey_lib wasm viability tested at T4 before UI work begins; fallback is vendoring `verify` paths (~150 lines) behind a feature.
- Type names consistent: `AttestationV1`, `FeedStateV1`, `InboxStateV1`, `ReplyPointer` used identically across tasks.
