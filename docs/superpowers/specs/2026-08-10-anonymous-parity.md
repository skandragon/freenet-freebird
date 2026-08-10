# Anonymous-user parity: two-tier slots + anchor cells

Date: 2026-08-10
Status: implemented (issue #23)
Plan: `docs/superpowers/plans/2026-08-10-anonymous-parity.md`

## Problem

The Ghost Key attestation doubled as the write gate on the two open-write
contracts (inbox, directory), locking anonymous users out of threads,
Discover, and Followers. The attestation never carried authenticity —
everything is signed by the posting key — so the gate can be replaced by a
slot POLICY without weakening any trust property.

## Two-tier slot policy

Both open-write contracts share the same shape:

| | inbox v2 | directory v2 |
|---|---|---|
| total cap | `MAX_POINTERS = 300` | `MAX_LISTINGS = 1000` |
| anonymous share | `ANON_POINTER_SLOTS = 100` | `ANON_LISTINGS = 250` |
| per-key cap | attested 8 / anon 3 per fingerprint | 1 per posting key (map key) |

- **Fingerprints**: attested = ghostkeys convention (`bs58(blake3(vk)[..8])`
  of the ghost key); anonymous = `"anon:" + bs58(blake3(posting_key))` (full
  hash — a truncated one would make targeted cap-group collisions
  borderline-feasible). The `anon:` prefix is the tier discriminator; merge
  code enforces `pointer.fingerprint == cred.fingerprint()`, so tiers cannot
  be spoofed.
- **Eviction** (deterministic, `(time, id)` order): anonymous evicts
  anonymous, never attested; attested evicts anonymous at the global cap;
  attested evicts attested only when attested alone exceed the total cap.
  The checkmark's functional meaning is now "durable, uncrowdable presence".
- **Horizons**: per tier — `Open` / `OldestRetained(key)` / `Closed`
  (`Closed` = attested writers hold every slot; senders offer nothing).
  Per-fingerprint horizons as v1, with the tier's cap. Same
  re-offer-livelock rationale as v1, split by tier because tiers evict
  independently.
- **Cred upgrade**: one posting key's cred goes anon→attested in place
  (attested content-hash always beats the anon all-zero hash). Old
  anon-fingerprint pointers are dropped by cleanup, and fingerprint
  mismatches drop pointers rather than fail deltas — an honest peer's delta
  is never poison-pilled by the upgrade race.

## Where the code lives (frozen-crate discipline)

`freebird-core` and `cell-contract` are byte-frozen: any edit rotates every
derived address including feeds and the delegate (stored posting keys!).
Therefore:

- Inbox v2 types: `contracts/inbox-contract/src/state.rs` (same pattern as
  the directory). `freebird_core::inbox` remains the v1 decoder.
- Directory v2: `contracts/directory-contract` in place, with a `legacy`
  module holding the v1 wire types for decode.
- Only the inbox and directory addresses rotated. Feeds, avatars, delegate,
  and cells are untouched.

## Anchor cells (the last hard rotation)

Each author owns a cell (`cell-contract`, `purpose = "anchor"`) whose
address derives from the FROZEN cell wasm + their posting key — stable
forever. Body (`anchor/` crate, client-side only, decode-tolerant like the
control schema):

```
AnchorV1 { v: 1, roles: { "inbox": { version: 2, address: Some(<32 bytes>) } } }
```

Owners (re)publish the anchor + an empty v2 inbox Put on every
create/resume (idempotent). Readers subscribe to the anchor alongside the
feed; a future v3 rotation publishes a new role entry instead of stranding
readers — clients that know the anchor can GET by the address it names
without holding the wasm that derives it.

## Migration / rollback

- **Dual-read window**: clients read v2 + legacy v1 inboxes/directories and
  merge in the UI (dedup by `(replier, reply_post)` / author). The v1 wasm
  bytes are vendored as `ui/contracts/*_v1.wasm` for address derivation
  only; never instantiated.
- **Window close**: publisher flips control flags `read_v1_inbox` /
  `read_v1_directory` to false
  (`freebird-ctl publish-control ... --flag read_v1_inbox=false`), stopping
  the legacy fetches network-wide without a client release. Default is ON.
- **Writes**: v2 only, from day one. The v1 contracts decay naturally.
- **Directory seed** bumped to `freebird-directory-v2` so the rotation is
  explicit in params, not just wasm bytes.
- **Listing tier upgrade**: a listed account that completes verification
  republishes its listing immediately (anon → attested tier).

## UI surface

The checkmark render sites are unchanged — it is now the ONLY visible
difference between anonymous and verified accounts. Removed: the anonymous
reply warning, the "verified accounts only" listing gate, the "anonymous
followers stay invisible" copy. Reply counts and threads count all replies;
Verification copy explains durability instead of permission.
