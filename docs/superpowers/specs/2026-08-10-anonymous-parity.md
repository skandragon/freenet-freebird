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
  Per-fingerprint horizons (inbox only) as v1, with the tier's cap; the
  directory's per-key fairness is the per-author LWW map itself. Same
  re-offer-livelock rationale as v1, split by tier because tiers evict
  independently. Directory deltas horizon-gate only authors the peer does
  not already hold (in-place LWW upgrades bypass the gate).
- **Cred upgrade**: one posting key's cred goes anon→attested in place
  (attested content-hash always beats the anon all-zero hash). Old
  anon-fingerprint pointers are dropped by cleanup, and fingerprint
  mismatches drop pointers rather than fail deltas — an honest peer's delta
  is never poison-pilled by the upgrade race.
- **Downgrade resistance**: the directory listing signature covers only the
  listing, so the LWW key ranks `(last_active, attested, hash)` — a
  stripped-attestation re-wrap of a victim's listing can never beat the
  attested original at equal time.

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

Owners (re)publish the anchor + a seed Put of their v2 inbox AND feed on
every create/resume (idempotent — both contracts merge a re-Put to a no-op,
and the feed seed is versioned below any real profile/follows so it cannot
clobber them). The feed half is issue #79: the feed rotated after this was
written (#64, #67), and an account that never re-Put it can only Update a
contract its node does not have. Readers subscribe to the anchor alongside the
feed; a future v3 rotation publishes a new role entry instead of stranding
readers — clients that know the anchor can GET by the address it names
without holding the wasm that derives it.

## Migration / rollback

- **Dual-read window**: clients read v2 + legacy v1 inboxes/directories and
  merge in the UI (dedup by `(replier, reply_post)` / author). The v1 wasm
  bytes are vendored as `ui/contracts/*_v1.wasm` for address derivation
  only; never instantiated.
- **Forward migration** (issue #56): the dual-read window is a bridge, not
  the migration. `actions::migrate_v1` runs once per account (delegate
  marker `v1_migration`: absent → `<start_ms>` → `done`) and re-signs our
  own v1-era data into the v2 contracts — legacy feed posts (ids survive;
  only the signing payload changed in #47), a v3 inbox pointer per v1-era
  reply, and a follow announcement per current follow. Retries every session
  until it marks `done`, reusing the stored start stamp so re-sent
  announcements keep the same PostIds and dedup. Directory listings need no
  extra step: `App`'s listing-refresh effect already republishes ours under
  the v2 key once per session.
  Ceiling: pointers we *received* in v1 are signed by their repliers, so
  only those repliers can carry them forward — the window is safe to close
  once enough of the network has come back and run this, not on a date.
- **Window close**: publisher flips control flags `read_v1_inbox` /
  `read_v1_directory` / `read_v1_feed` to false
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
