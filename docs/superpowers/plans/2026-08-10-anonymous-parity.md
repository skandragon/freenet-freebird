# Anonymous-User Parity (issue #23) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Anonymous accounts participate exactly like verified ones — replies in threads, Discover listings, follower visibility — with the checkmark meaning "durable, uncrowdable presence" instead of "allowed to exist"; the rotation of the inbox + directory contract addresses rides a new per-author anchor-cell routing layer so this is the last hard migration.

**Architecture:** Two-tier slot policy in the inbox and directory contracts (attested writers always win eviction; anonymous writers fill a bounded share and evict only each other, fingerprinted by `blake3(posting_key)`). V2 inbox state types live in the `inbox-contract` crate (NOT `freebird-core`, which is byte-frozen — any edit there rotates every contract including feeds and the delegate). Readers dual-read v1 + v2 inboxes/directories during a migration window gated by control-cell flags; owners republish v2 inboxes and publish anchor cells (frozen `cell-contract` kernel, `purpose = "anchor"`) mapping role → version/address.

**Tech Stack:** Rust workspace; freenet-stdlib 0.8.5, freenet-scaffold (composable macro), ed25519-dalek, blake3, ciborium CBOR; Dioxus 0.7 web UI.

## Global Constraints

- **`common/` (freebird-core) is FROZEN.** No edits of any kind — a byte change rotates all contract addresses and the delegate key (2026-08-10 avatar incident).
- **`contracts/cell-contract` is FROZEN.** Same rule; the anchor system reuses the existing vendored wasm.
- Feed, avatar, cell, delegate wasm hashes in `scripts/wasm-hashes.txt` must be byte-identical after `make contracts`/`make delegate`. Only `inbox_contract.wasm` and `directory_contract.wasm` re-pin.
- Contract crates compiled to wasm: never add `rand` or a getrandom backend feature; wasm imports must stay in `freenet_` namespaces (`make check-imports`).
- Contract wasm must never panic — reject with `ContractError`, tolerate unknown enum variants.
- Merge functions must be pure/deterministic (no clocks, no randomness); clock scrubbing only in the contract shell.
- All CBOR via `to_cbor`/`from_cbor` helpers; state canonicalization idempotent; convergence proptested.
- Constants (locked by this plan): inbox `MAX_POINTERS = 300`, `ANON_POINTER_SLOTS = 100`, `MAX_PER_FINGERPRINT = 8` (attested), `MAX_PER_ANON_KEY = 3`; directory `MAX_LISTINGS = 1000`, `ANON_LISTINGS = 250`; directory seed becomes `"freebird-directory-v2"`; anchor purpose `"anchor"`; anchor role key `"inbox"` with version `2`.
- Fingerprint namespaces: attested = `att.fingerprint()` (ghostkeys bs58 convention, unchanged); anonymous = `"anon:" + bs58(blake3(posting_key bytes))` (full 32-byte hash — an 8-byte prefix would make targeted fairness-group collisions borderline-feasible). The `anon:` prefix is the tier discriminator inside `canonicalize`, and `verify`/`apply` enforce `pointer.fingerprint == cred.fingerprint()` so tiers can't be spoofed.

---

### Task 1: Branch + legacy wasm vendoring + Makefile build isolation

**Files:**
- Create: `ui/contracts/inbox_contract_v1.wasm`, `ui/contracts/directory_contract_v1.wasm` (byte copies of the current vendored wasm)
- Modify: `Makefile` (move `inbox-contract` out of the joint feed/avatar cargo invocation into its own, like directory; keep feed+avatar joint)

**Interfaces:**
- Produces: frozen v1 wasm bytes at stable paths for v1 address derivation (Task 6). `scripts/wasm-hashes.txt` is NOT re-pinned yet (Task 9).

- [ ] **Step 1:** `git checkout -b feat/anonymous-parity`
- [ ] **Step 2:** `cp ui/contracts/inbox_contract.wasm ui/contracts/inbox_contract_v1.wasm && cp ui/contracts/directory_contract.wasm ui/contracts/directory_contract_v1.wasm`
- [ ] **Step 3:** Makefile: build `-p inbox-contract` in its own cargo invocation (new deps must not feature-unify into feed/avatar bytes); adjust comments.
- [ ] **Step 4:** Commit: `chore: vendor v1 inbox/directory wasm for dual-read; isolate inbox build`

### Task 2: `freebird-anchor` crate (client-side anchor schema)

**Files:**
- Create: `anchor/Cargo.toml`, `anchor/src/lib.rs`
- Modify: `Cargo.toml` (workspace member; `freebird-anchor = { path = "anchor" }` workspace dep)

**Interfaces:**
- Produces:
  - `pub const ANCHOR_PURPOSE: &str = "anchor"`
  - `pub struct RoleV1 { pub version: u32, #[serde(default)] pub address: Option<[u8; 32]> }`
  - `pub struct AnchorV1 { pub v: u32, #[serde(default)] pub roles: BTreeMap<String, RoleV1> }`
  - `impl AnchorV1 { pub fn decode(body: &[u8]) -> Option<Self>; pub fn encode(&self) -> Vec<u8>; pub fn role(&self, name: &str) -> Option<&RoleV1> }`
  - `pub fn anchor_params(owner: &VerifyingKey) -> cell_contract::CellParametersV1` (purpose `"anchor"`)
- Consumes: `cell-contract` (default-features = false) for CBOR helpers + params type.

Mirror `control/src/lib.rs` structure and its decode-tolerance doctrine (undecodable ⇒ `None`, never a user-visible error; unknown fields ignored).

- [ ] **Step 1:** Write tests first in `anchor/src/lib.rs` `#[cfg(test)]`: roundtrip; unknown-fields tolerated; garbage/empty ⇒ `None`; `role()` lookup; `anchor_params` purpose.
- [ ] **Step 2:** `cargo test -p freebird-anchor` — fails (types missing).
- [ ] **Step 3:** Implement schema + helpers.
- [ ] **Step 4:** `cargo test -p freebird-anchor` — passes.
- [ ] **Step 5:** Commit: `feat: freebird-anchor client-side schema for per-author anchor cells`

### Task 3: Inbox v2 — two-tier state types in `inbox-contract`

**Files:**
- Create: `contracts/inbox-contract/src/state.rs` (v2 composable state; ~mirror of `common/src/inbox.rs` with tier policy)
- Modify: `contracts/inbox-contract/src/lib.rs` (becomes `pub mod state;` + `#[cfg(feature = "freenet-main-contract")] mod contract` shell over V2, gated like directory-contract)
- Modify: `contracts/inbox-contract/Cargo.toml` (add `blake3.workspace = true`, `freenet-scaffold-macro`, dev-dep `proptest`; `[lib] rlib` already present)

**Interfaces:**
- Produces (all in `inbox_contract::state`):
  - `pub const MAX_POINTERS: usize = 300; pub const ANON_POINTER_SLOTS: usize = 100; pub const MAX_PER_FINGERPRINT: usize = 8; pub const MAX_PER_ANON_KEY: usize = 3;`
  - `pub struct InboxParametersV2 { pub owner: VerifyingKey, pub ghostkey_master: VerifyingKey }` (CBOR-identical shape to v1 params)
  - `pub struct ReplierCredV2 { pub posting_key: VerifyingKey, pub attestation: Option<AttestationV1> }` with `fn check(&self, map_key, master) -> Result<(), String>` (verify chain only when `Some`) and `pub fn fingerprint(&self) -> String` (namespaced per Global Constraints)
  - `pub fn anon_fingerprint(posting_key_bytes: &[u8; 32]) -> String`
  - `pub struct ReplyPointerV2 { pub replier: [u8; 32], pub fingerprint: String, pub target_post: PostId, pub reply_post: PostId, pub time: u64 }`
  - `pub struct AuthorizedReplyPointerV2 { pub ptr: ReplyPointerV2, pub signature: Signature }` with `new(ptr, &SigningKey)` / `verify_signature(&VerifyingKey)` (same CBOR-sign scheme as v1)
  - `pub enum TierHorizon { Open, OldestRetained(PointerOrderKey), Closed }` — `Closed` = "this tier retains nothing and accepts nothing" (attested tier fills all slots), so senders offer nothing rather than livelock
  - `#[composable(post_apply_delta = "post_apply_cleanup")] pub struct InboxStateV2 { pub creds: CredsV2, pub pointers: PointersV2 }` (creds field FIRST — field order is load-bearing for self-contained deltas) + generated `InboxStateV2Delta`, `InboxStateV2Summary`
  - `PointersV2Summary { ids, attested_horizon: TierHorizon, anon_horizon: TierHorizon, fp_horizons: BTreeMap<String, PointerOrderKey> }`
  - `InboxStateV2::scrub_future(&mut self, now_ms)`
- Consumes: `freebird_core::attestation::AttestationV1` (+ `fixtures::TestAuthority` in tests), `freebird_core::types::PostId`, `freebird_core::to_cbor`.

**Slot policy (`PointersV2::canonicalize`, pure fn of the pointer set, idempotent):**
1. Sort ascending by `(time, reply_post)`; dedup by `reply_post`.
2. Per-fingerprint cap, newest kept: cap = `MAX_PER_ANON_KEY` if fingerprint starts with `"anon:"` else `MAX_PER_FINGERPRINT`.
3. Anonymous share: keep only the newest `ANON_POINTER_SLOTS` anonymous pointers.
4. Global cap: while `len > MAX_POINTERS`, evict the OLDEST anonymous pointer; only when no anonymous remain, evict the oldest attested. (Verified-never-evicted-by-anon; anon evict each other with the deterministic `(time, reply_post)` order.)

**Horizons (in `summarize`):**
- `attested_horizon = OldestRetained(oldest attested key)` iff attested count `== MAX_POINTERS`, else `Open`. (Never `Closed`.)
- effective anon cap = `min(ANON_POINTER_SLOTS, MAX_POINTERS - attested_count)`; `anon_horizon = Closed` if effective cap is 0, `OldestRetained(oldest anon key)` iff anon count `== effective cap`, else `Open`.
- `fp_horizons`: for each fingerprint AT its tier cap, the oldest retained key (same livelock rationale as v1).
- `delta()` offers a pointer only if peer lacks it AND it clears the tier horizon for its own tier AND clears its fp_horizon.

**`verify` invariants:** sorted; no dup `reply_post`; every pointer has a cred, valid signature, `fingerprint == cred.fingerprint()`; total ≤ `MAX_POINTERS`; anon count ≤ `ANON_POINTER_SLOTS`. `CredsV2` verify/apply: len bound ≤ `MAX_POINTERS` per delta (each attested cred costs an RSA chain verify in wasm); LWW per key by attestation-content-hash with `None` attestation hashing as `[0u8; 32]` so an attested cred always beats an anonymous one for the same posting key (an author who verifies upgrades in place, and the max-hash rule stays deterministic).

- [ ] **Step 1:** Write `state.rs` tests first (port every v1 test, then add):
  - `anon_pointer_accepted_and_state_verifies` (cred with `attestation: None`)
  - `attested_pointer_accepted_and_state_verifies`; `pointer_without_cred_dropped`; `cred_with_bad_attestation_rejected`; `forged_pointer_signature_rejected`; `wrong_tier_fingerprint_rejected` (anon cred + attested-style fingerprint on pointer ⇒ error)
  - `anon_per_key_cap_is_3`; `attested_per_fingerprint_cap_is_8`
  - `anon_share_capped_at_100` (101 distinct anon keys × 1 pointer ⇒ 100 retained, oldest dropped)
  - `anon_never_evicts_attested` (fill 250 attested + flood 200 anon ⇒ all 250 attested retained, 50 anon)
  - `attested_evicts_anon_at_global_cap` (100 anon + 300 newer attested ⇒ 0 anon, 300 attested — checkmark = uncrowdable)
  - `attested_only_eviction_when_no_anon_left` (301+ attested ⇒ oldest attested dropped)
  - `anon_closed_horizon_prevents_reoffer_livelock` (receiver full of attested ⇒ sender with anon pointers produces no delta)
  - `anon_fp_horizon_prevents_flood_reoffer_livelock` (port of v1 fp test at cap 3)
  - `same_ghostkey_second_posting_key_does_not_brick_inbox` (port); `orphan_creds_pruned`; `oversized_cred_delta_rejected`
  - `attested_cred_beats_anon_cred_for_same_key` (LWW upgrade)
  - proptests: `merge_commutative` (mixed anon/attested writers, byte-identical convergence), `cleanup_idempotent`
- [ ] **Step 2:** `cargo test -p inbox-contract` — fails to compile (types missing).
- [ ] **Step 3:** Implement `state.rs` (adapt `common/src/inbox.rs`, apply the policy above) and rewire `lib.rs` shell to V2 types behind the feature gate; `scrub_delta`/`scrub_future` unchanged in shape.
- [ ] **Step 4:** `cargo test -p inbox-contract` — passes. Also `cargo test -p freebird-core` (v1 untouched, still green).
- [ ] **Step 5:** Commit: `feat: two-tier inbox v2 — anonymous creds with bounded slot share`

### Task 4: Directory v2 — optional attestation, two-tier eviction

**Files:**
- Modify: `contracts/directory-contract/src/lib.rs` (rename state types → V2, add tier policy, add frozen `pub mod legacy` with the v1 decode types)

**Interfaces:**
- Produces: `DIRECTORY_SEED = "freebird-directory-v2"`; `MAX_LISTINGS = 1000`; `ANON_LISTINGS = 250`; `DirectoryParametersV2` (same shape); `ListingV1` (unchanged shape, kept name); `AuthorizedListingV2 { listing, signature, attestation: Option<AttestationV1> }` (`check` verifies chain only when `Some`; `is_anon()`); `DirectoryStateV2 { listings: BTreeMap<[u8;32], AuthorizedListingV2> }` with `verify/canonicalize/scrub_future/summarize/delta/apply_delta/merge`; `DirectorySummaryV2 { entries, attested_horizon: TierHorizon, anon_horizon: TierHorizon }` (local `TierHorizon` enum, same semantics as inbox); `pub mod legacy { pub const DIRECTORY_SEED_V1; LegacyListing = ListingV1 shape; LegacyAuthorizedListing { listing, signature, attestation: AttestationV1 }; LegacyDirectoryState { listings }; fn check(...) }` — decode + check only, for the UI's dual-read.
- Eviction: per-author LWW as today (one listing per key = the anon per-key cap); over `ANON_LISTINGS` anon ⇒ evict oldest anon; over `MAX_LISTINGS` total ⇒ evict oldest anon first, oldest attested only when no anon remain. `verify`: total ≤ 1000, anon ≤ 250. Horizons: attested `OldestRetained` iff attested `== MAX_LISTINGS`; anon `Closed`/`OldestRetained`/`Open` per effective cap `min(ANON_LISTINGS, MAX_LISTINGS - attested)`. `delta()` filters per-tier.

- [ ] **Step 1:** Update/extend tests first: port all existing (renamed types); add `anon_listing_accepted`; `anon_share_capped`; `anon_never_evicts_attested`; `attested_evicts_anon_at_cap`; `closed_anon_horizon_no_reoffer`; `legacy_decode_roundtrip` (legacy types decode bytes produced by legacy encode; check rejects missing attestation).
- [ ] **Step 2:** `cargo test -p directory-contract` — fails.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test -p directory-contract` — passes.
- [ ] **Step 5:** Commit: `feat: directory v2 — anonymous listings with bounded share`

### Task 5: UI plumbing — keys, state, api (dual-read + anchors)

**Files:**
- Modify: `ui/Cargo.toml` (add `inbox-contract` + `freebird-anchor`, both default-features = false where applicable)
- Modify: `ui/src/keys.rs`, `ui/src/state.rs`, `ui/src/api.rs`

**Interfaces:**
- `keys.rs` produces: `INBOX_V1_CONTRACT_WASM`/`DIRECTORY_V1_CONTRACT_WASM` (include_bytes of the `_v1.wasm` files); `inbox_params` returns `inbox_contract::state::InboxParametersV2`; `inbox_key/inbox_instance_id` (v2 wasm); `inbox_key_v1/inbox_instance_id_v1` (v1 wasm + `freebird_core::inbox::InboxParametersV1`); `directory_params` (V2, seed v2) + `directory_key/directory_instance_id`; `directory_key_v1/directory_instance_id_v1` (v1 wasm + legacy params, seed `"freebird-directory-v1"`); `anchor_params(owner)`, `anchor_key(owner)`, `anchor_instance_id(owner)` (CELL_CONTRACT_WASM + purpose "anchor").
- `state.rs` produces: `INBOXES: BTreeMap<[u8;32], InboxStateV2>`; `LEGACY_INBOXES: BTreeMap<[u8;32], freebird_core::inbox::InboxStateV1>`; `DIRECTORY: Option<DirectoryStateV2>`; `LEGACY_DIRECTORY: Option<legacy::LegacyDirectoryState>`; `ANCHORS: BTreeMap<[u8;32], Option<freebird_anchor::AnchorV1>>`; helper `pub fn flag_bool(name, default) -> bool` reading `CONTROL`.
- `api.rs` produces: `TrackedKind::{Inbox, LegacyInbox, Anchor, LegacyDirectory}` variants + dispatch arms (v2 inbox merge/delta like today but V2 types; legacy inbox merge full-state/delta into `LEGACY_INBOXES` using v1 types — reuse existing v1 code shape; legacy directory full-state/delta into `LEGACY_DIRECTORY` via `legacy` module `check` per listing, LWW insert; anchor = `SignedCellV1` bytes, `cell.check(&keys::anchor_params(&vk))` then `AnchorV1::decode`, keep newest by `order_key`, store `ANCHORS`); `fetch_feed` additionally GETs anchor cell (subscribe) and, when `flag_bool("read_v1_inbox", true)`, the v1 inbox (subscribe); `fetch_directory` also GETs legacy directory when `flag_bool("read_v1_directory", true)`; `put_own_contracts` PUTs v2 inbox; new `pub async fn publish_anchor(sk: &SigningKey) -> Result<(), String>` (body = `AnchorV1 { v: 1, roles: { "inbox" => RoleV1 { version: 2, address: Some(inbox_instance_id bytes) } } }`, `SignedCellV1::new(sk, "anchor", keys::now_ms(), body)`, Put with cell container + subscribe false); `update_inbox` takes `InboxStateV2Delta`.

- [ ] **Step 1:** Implement all of the above.
- [ ] **Step 2:** `cargo check -p freebird-ui` (native check; wasm-only code is cfg-gated) — expect remaining errors only in `actions.rs`/`views.rs` (fixed next tasks); iterate until the only errors are those.
- [ ] **Step 3:** Commit with Task 6 (workspace must compile per-commit — Tasks 5–7 land as one commit if intermediate states don't build; prefer one commit `feat: dual-read plumbing + anchor cells in UI`).

### Task 6: Actions — drop the three gates, owner republish

**Files:**
- Modify: `ui/src/actions.rs`

**Interfaces:**
- `send_inbox_pointer(sk, attestation: Option<AttestationV1>, target_author, target_post, reply_post, time)` — builds `ReplierCredV2 { posting_key, attestation }`, `fingerprint = cred.fingerprint()`, `InboxStateV2Delta`.
- `publish_post`: replies ALWAYS send the pointer (`own_feed().and_then(|f| f.attestation.0)` passed as the Option, no gate).
- `set_follow`: ALWAYS announces (attestation as Option); comment updated.
- `set_public_listing(on)`: no attestation requirement; `AuthorizedListingV2::new(listing, &sk, att_option)`.
- `create_account`: after `put_own_contracts`, call `api::publish_anchor(&sk)` (best-effort log on error).
- `resume_account`: after `fetch_feed`, spawn best-effort owner republish: PUT v2 inbox via new `api::ensure_own_inbox(&vk)` (Put of default `InboxStateV2` — contract merge makes this idempotent) + `api::publish_anchor(&sk)`.
- `complete_verification`: after publishing the attestation, re-send directory listing if `PUBLIC_LISTING == Some(true)` (upgrade listing to attested tier).

- [ ] **Step 1:** Implement; `cargo check -p freebird-ui` until only `views.rs` errors remain.
- [ ] **Step 2:** Commit together with Task 5/7 as needed.

### Task 7: Views — merged dual-read rendering, copy updates

**Files:**
- Modify: `ui/src/views.rs`

**Changes:**
- Helper `fn pointers_for(author) -> Vec<(replier, target_post, reply_post, time, has_cred)>`-style accessor merging `INBOXES` (v2) + `LEGACY_INBOXES` (v1), dedup by `(replier, reply_post)` — used by `PostCard` reply counts, `Thread`, `FollowersBox`, and the missing-feed fetch effects.
- `Compose`: delete the `if is_reply && !own_verified` warning block and the `verified_now` fork (notice: "Reply posted to the thread."); drop now-unused `own_verified` binding.
- `Thread`: "No verified replies yet." → "No replies yet."
- `FollowersBox` empty copy: "No followers yet. Followers appear here once their follow announcement reaches your inbox." `verified_followers` refactored to take the merged pointer list; test updated. Section title stays "Followers".
- `PublicListingToggle`: toggle for everyone; delete the "Get a check mark to list yourself" branch.
- `Discover`: listings = v2 map merged with legacy map (v2 wins per author; else newest `last_active`); render unchanged (checkmark still from feed attestation via `is_verified`).
- `App` listing-refresh effect: drop the `verified` condition.
- `VerifyBox` copy — unverified: "Anonymous accounts have full run of Freebird — peep, reply into threads, get listed in Discover. A Ghost Key adds the check mark and makes your presence durable: verified replies and listings are never crowded out by the anonymous crowd." Verified: "This account has earned the Prized Checkmark. Your replies and listings can never be crowded out."
- Checkmark render sites: UNCHANGED (the only visible difference).
- Re-test the parent-present hide rule: with dual-write now on, an anonymous reply reaches the thread, so the `views.rs` timeline hide rule no longer orphans it — covered by the existing rule + new thread merge; add a views test that an anon announcer shows in `verified_followers` given a confirming feed, and one that reply merging dedups a pointer present in both v1 and v2.

- [ ] **Step 1:** Implement; `cargo check -p freebird-ui` clean; `cargo test -p freebird-ui` (views tests) green.
- [ ] **Step 2:** Commit Tasks 5–7: `feat: anonymous parity in client — dual-read, anchors, gates removed`

### Task 8: Workspace green + wasm rebuild + hash re-pin

- [ ] **Step 1:** `make test` (`cargo test --workspace`) — all green.
- [ ] **Step 2:** `make contracts` — EXPECT check-addresses failure listing exactly `inbox_contract.wasm` + `directory_contract.wasm`. Verify feed/avatar/cell hashes unchanged (`shasum -a 256 -c scripts/wasm-hashes.txt | grep -v OK`). If feed/avatar/cell changed: STOP, fix build isolation (feature unification), do not pin.
- [ ] **Step 3:** `make pin-hashes` (now also pins the two `_v1.wasm` copies); `make delegate` to confirm delegate hash stable; `make ui` builds.
- [ ] **Step 4:** Commit: `feat: rebuild + pin v2 inbox/directory wasm (deliberate rotation, rides anchor cells)`

### Task 9: Docs + PR

- [ ] **Step 1:** Write `docs/superpowers/specs/2026-08-10-anonymous-parity.md` — condensed spec: tier policy tables, fingerprint namespaces, horizon semantics, anchor schema, migration/rollback story (flags `read_v1_inbox` / `read_v1_directory`, publisher flips them off once the window closes via `freebird-ctl publish-control --flag`).
- [ ] **Step 2:** Push branch, open PR referencing #23 with the work-item checklist mapped to commits.

## Post-Review Deviations (PR #24 review pass)

- Fingerprint mismatch in a delta is DROPPED, not an error (test renamed
  `wrong_tier_fingerprint_dropped`): the anon→attested cred upgrade makes
  mismatches an honest race, and an error would poison-pill peers' deltas.
  Fabricated full states with mismatches still fail `verify`.
- `canonicalize` dedups `reply_post` set-based, not adjacency-based — the
  (time, reply_post) sort separates equal reply_posts, and adjacency dedup
  let a free key brick an inbox (apply-accepts / verify-rejects).
- Directory `lww_key` is `(last_active, attested, hash)`: the signature
  covers only the listing, so an attestation-stripping re-wrap must never
  win the equal-time tie-break.
- `update_inbox` is a Put (creates the target's v2 inbox on first write),
  not an Update: during the migration window most targets' v2 inboxes do
  not exist yet and an Update would fail asynchronously and invisibly.
- `verify` also enforces the per-fingerprint caps; anchor `decode` enforces
  the `v >= 1` floor; tier decisions (reply pointer, listing) require the
  own feed to be loaded so a cold start can't publish at the wrong tier.

## Self-Review Notes

- Spec coverage: issue work items → Task 3 (slot policy + merge tests), Task 3 (`inbox.rs` v2 equivalent — relocated to inbox-contract per frozen-core constraint, superseding the issue's `common/src/inbox.rs` pointer), Task 4 (directory), Tasks 1/2/5/6 (anchors + v2 migration + dual-read), Task 6 (three gates), Task 7 (UI + parent-present rule), Task 8 (address rotation done deliberately).
- Deviation from issue text, justified: issue says modify `common/src/inbox.rs`; doing so rotates feed + delegate addresses (losing posting keys). V2 types in `inbox-contract` achieve the same semantics with a strictly smaller blast radius.
- Type-consistency: `InboxStateV2Delta`/`InboxParametersV2` names used in Tasks 5–6 match Task 3's produces; `AuthorizedListingV2`/`DirectoryStateV2`/`legacy::*` in Tasks 5–7 match Task 4.
