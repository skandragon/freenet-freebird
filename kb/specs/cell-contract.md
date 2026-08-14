---
type: spec
title: The cell contract — a frozen signed-cell kernel
description: One owner-signed opaque body per cell, merged by highest (seq, hash). The contract never decodes the body, so client schemas evolve freely while the wasm stays byte-identical forever — the escape hatch from content-derived address rotation. Carries the control channel and the PoW difficulty record.
timestamp: 2026-08-14T00:00:00Z
status: living
covers:
  - contracts/cell-contract/**
  - control/**
  - tools/freebird-ctl/**
---

The general answer to addresses rotating on every schema change: a kernel whose
validation never depends on the payload's shape. See
[address derivation and rotation](address-derivation.md) for why that matters.

- Parameters are `{owner, purpose}`, so one wasm serves an unlimited number of
  distinct cells. State is a single signed body, at most 64 KiB, opaque to the
  contract.
- The signature covers a domain tag, the purpose (length-prefixed), the sequence
  number, and the hash of the body. Binding the purpose into the signed payload
  is what stops a cell being replayed as a different cell under the same owner.
- MUST merge by highest `(seq, hash-of-encoding)`. The sequence convention is
  unix milliseconds at publish time, so lowering a published value means
  republishing the lower value at a *higher* seq.
- MUST NOT decode the body in the contract. That single restraint is what lets
  the wasm stay byte-identical forever while the schemas riding on it change.

Purposes in use:

- `control` — the deployed build number, a build label, and feature flags.
  Drives the update banner and the dual-read window's per-role kill switches.
- `pow` — the publisher-signed anonymous proof-of-work bar. A distinct address
  from the control cell, so a build record can never be read as a difficulty
  record. See [anonymous-PoW difficulty](anon-pow-difficulty.md).
- Planned: per-author anchor and routing cells mapping a role to its current
  contract address and version, for migration across rotations.

⚠ This crate is FROZEN. It has no dependency on the shared core crate, so
routine edits have no path into its bytes — and rebuilding it is, by definition,
minting a different contract. The vendored blob is sha-pinned and must never
change again.

Design record: [`docs/superpowers/specs/2026-08-10-control-cell-design.md`](../../docs/superpowers/specs/2026-08-10-control-cell-design.md).
