# Control cell: update banner + future feature flags

Date: 2026-08-10
Status: approved

## Problem

The UI is a Freenet website contract; users on stale bundles (long-lived tabs,
propagation skew) don't know a newer build exists. We also want a network-wide
channel for feature flags and staged rollouts. Contract addresses are
content-derived (`hash(params + wasm)`), so any schema/wasm change rotates the
address — the channel itself must never need to rotate.

## Design

### 1. Cell contract (`contracts/cell-contract`) — frozen kernel

A minimal "signed mutable cell" contract that never decodes its payload:

- Params: `CellParametersV1 { owner: VerifyingKey, purpose: String }` — one
  wasm serves many cells; this feature uses `purpose = "control"`, the future
  per-author anchor system reuses the same kernel with other purposes.
- State: `SignedCellV1 { seq: u64, body: Vec<u8> (opaque, ≤ 64 KiB), sig }`.
  Signature by `params.owner` over the domain-separated payload
  `"freebird-cell-v1" || len(purpose) || purpose || seq_le || blake3(body)`.
  Binding `purpose` blocks replaying one cell's record into another cell
  owned by the same key.
- Merge: valid signature required; higher `(seq, blake3(state bytes))` wins.
  Summary = that order key; delta = the full cell (it's tiny).
- The wasm is built once, vendored in `ui/contracts/cell_contract.wasm`,
  pinned in `scripts/wasm-hashes.txt`, and never rebuilt. Rebuilding it is by
  definition a new contract. The crate takes no freebird-core dependency so
  there is never a reason to touch it.

### 2. Control schema (`control/` crate, `freebird-control`) — client-side only

The contract never sees this; it can grow without touching wasm:

```
ControlV1 { v: 1, build: u64, build_label: String, flags: BTreeMap<String, Value> }
```

- `build` = git commit count (ordering), `build_label` = short hash (display).
- Decoding ignores unknown fields; undecodable/missing body ⇒ behave as if no
  control state exists (no banner, all flags default).
- Holds the compiled-in publisher public key and `control_params()`.
- Shared by the UI and the publish CLI; contracts do not depend on it.

### 3. Publisher key

Ed25519 keypair; secret at `~/.freebird/publisher.key` (32-byte seed, hex,
mode 600 — back it up alongside the fdev site key). Public key compiled into
`freebird-control`. `seq` = unix millis at publish time (single publisher;
avoids a read-before-write).

### 4. Publish CLI (`tools/freebird-ctl`)

Native binary using freenet-stdlib's tokio websocket client against
`ws://localhost:7509` (same tunnel as fdev):

- `keygen` — mint a publisher key (refuses to overwrite).
- `publish-control --build N --label H [--flag k=v]...` — sign and Put the
  cell (Put creates on first use; the contract's merge handles later ones).
- `show` — fetch and print the current control cell, for verification.

`make publish` chains: build → publish site → `freebird-ctl publish-control`
with git-derived values, so the advertised build always matches the published
bundle.

### 5. UI

- `build.rs` additionally stamps `BUILD_NUMBER` (`git rev-list --count HEAD`);
  dev builds without git get 0, which disables the banner.
- Startup subscribes to the control cell like the directory; verified +
  decoded into a `CONTROL` signal.
- Banner at the top of the app shell when
  `control.build > own build && control.build > dismissed_build`:
  "A new version of Freebird is available — Reload". Reload =
  `location.reload()`; Dismiss stores the build number in the delegate KV
  (`dismissed_build`), hiding the banner until an even newer build appears.
- `flag_bool(name, default)` helper for future flags.

## Testing

- Cell contract: signature required; wrong owner rejected; cross-purpose
  replay rejected; higher seq wins; equal-seq tie-break deterministic;
  oversized body rejected; arbitrary bytes accepted when signed.
- Control schema: decode with unknown fields; garbage tolerated; flag helper
  defaults.
- Banner predicate: table test over (own build, control build, dismissed).

## Out of scope

Per-author anchor/routing cells, staged/percentage rollouts (the schema
admits them later), any change to existing contracts.
