# kb / specs

Intended behavior as atomic claims, each pointing at its implementation through
the `covers:` globs in its frontmatter. Start at the architecture entry for the shape of
the whole system; the rest are ordered along the lifetime of a contract — how
its address comes to exist, what merges into its state, what it costs to
validate, and what happens when its bytes change.

- [system architecture](architecture.md) — the pieces, the platform constraints
  that force that shape, and the questions to answer before adding a surface
- [address derivation and the rotation guard](address-derivation.md) — every
  address derives from wasm bytes; the 2026-08-10 incident that proved it, the
  pinned-hash guard, generation constants, and the cumulative delegate registry
- [the cell contract](cell-contract.md) — the frozen signed-cell kernel with an
  opaque body, carrying the control channel and the PoW difficulty record; the
  escape hatch from schema-driven rotation
- [CRDT merge rules](crdt-merge-rules.md) — content-hash LWW summaries,
  credentials keyed by posting key, a retention horizon per prune rule, content
  ids that hash every field
- [anonymous-PoW difficulty](anon-pow-difficulty.md) — the publisher's bar is
  latched into state, not attached to a delta, so a raise binds attackers
- [full-state validate_state cost](validate-state-cost.md) — why the RSA
  attestation work in the full-state path cannot be cached, weakened, or skipped
- [the dual-read window](dual-read-window.md) — reading both generations across
  a rotation; the legacy-blob invariant, per-role terminators, and why the
  directory and inbox windows cannot close on a date
