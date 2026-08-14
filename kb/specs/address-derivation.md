---
type: spec
title: Address derivation, generations, and the rotation guard
description: Every contract and delegate address derives from wasm bytes, so any byte change rotates all of them and orphans posts and stored posting keys. Records the 2026-08-10 incident that proved it, the pinned-hash guard, the per-role generation constants, and the cumulative delegate registry.
timestamp: 2026-08-14T00:00:00Z
status: living
covers:
  - ui/src/keys.rs
  - scripts/wasm-hashes.txt
  - ui/contracts/**
---

Freenet addresses a contract by the hash of its code and parameters. Freebird
derives every per-author address — feed, inbox, avatar — and the delegate key
from the vendored wasm, so the bytes *are* the addressing truth. This is a
platform property, not a Freebird choice.

- MUST treat any change to vendored wasm bytes as a rotation of every derived
  address. Old state is not destroyed; it stays at the old address and simply
  stops being read by the new build.
- MUST NOT rotate as a side effect of a rebuild. Rotation is a deliberate,
  reviewed act carrying a migration story — see
  [the dual-read window](dual-read-window.md) and
  [reproducible builds](../policies/reproducible-builds.md).
- MUST bump the role's generation constant in the same change that rotates its
  wasm. The goldens pin each address next to the constant describing it, so a
  rotation that leaves the constant alone fails CI. [#80]
- MUST append to the delegate's legacy registry rather than replacing entries.
  The registry is cumulative across every generation ever shipped, because the
  startup probe folds each old generation's stored posting-key seed forward;
  overwriting the oldest entry destroys the seed of anyone still on it. [#53]

Anchor roles (feed, inbox, avatar) carry a generation constant. The directory is
a doorbell contract with no anchor role and no constant.

## The incident that set the rule

The 2026-08-10 avatar release (commit `45cd142`, [#10]) added avatar types to the
shared core crate. The feed contract, the inbox contract, and the delegate all
link that crate, so all of their bytes changed. Every per-author address rotated
and the delegate key changed: old peeps went invisible — still on the network at
their old addresses, but the new build derived new ones — and existing users
dropped back to onboarding, because their posting key was stored under the old
delegate key. The website contract was unaffected; a site update keeps its
address.

The reset was accepted that once. The standing decision from it: rotation must
never happen silently again, and an old-contract migration path must exist
*before* rotating.

## The guard

`make check-addresses` compares the vendored wasm against sha256 hashes pinned
in `scripts/wasm-hashes.txt` and fails loudly naming the drifted file. It runs at
the end of the contract and delegate build targets, before `make ui`, and in CI
against the committed bytes with no Rust build needed. `make pin-hashes` is the
deliberate re-pin — only with a migration plan.

`make check-built` is the same comparison applied to freshly built wasm *before*
it reaches the vendored directory, so a rotating build leaves `ui/contracts/`
byte-identical to what it was.

## Recovery, if it ever happens again

Old wasm bytes are in git history, so old addresses are re-derivable. Old posting
keys still live in the old delegate on users' nodes. A migration build can carry
both wasm generations, read from the old addresses, and republish under the new
ones — which is exactly what the dual-read window and the delegate seed-folding
probe now do as standing machinery.
