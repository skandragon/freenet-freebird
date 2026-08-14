---
type: spec
title: CRDT merge rules
description: Four merge rules, each a proven failure when violated — content-hash LWW summaries, credentials keyed by posting key not ghost fingerprint, a retention horizon per prune rule, and content ids that hash every content-bearing field. Plus the empty-summary and empty-state conventions every contract shell needs.
timestamp: 2026-08-14T00:00:00Z
status: living
covers:
  - common/src/**
  - contracts/feed-contract/src/**
  - contracts/inbox-contract/src/**
  - contracts/directory-contract/src/**
---

All four rules were violated once, found in adversarial review, and fixed
together in commit `971645c`. Regression tests pin each of them; the proptests
in `common/` exercise them against random interleavings.

- MUST make an LWW summary entry `(version, content-hash)`, with the winner the
  lexicographic maximum. A version-only summary leaves two peers holding
  *different* records at the same version looking permanently in-sync — the
  byte tie-break in the delta path is unreachable when the delta is never
  emitted.
- MUST key open-write credentials by the key that signatures verify against —
  the posting key — never by Ghost Key fingerprint. One Ghost Key legitimately
  attests many posting keys (every reinstall and re-verify mints another), so a
  fingerprint-keyed credential swap orphans every stored pointer and turns the
  state Invalid network-wide, with no self-healing path.
- MUST publish a retention horizon for every prune rule that can silently drop
  entries. A global-cap horizon does not cover a per-fingerprint fairness cap: a
  peer that dropped a flooder's excess still advertises Open, and is offered the
  same entries every round — a livelock that triggers precisely during spam.
  Freebird publishes `fp_horizons` (fingerprint → oldest retained) for any group
  sitting at its cap.
- MUST hash every content-bearing field into a content id. The post id
  originally skipped the reply target, so two valid posts collided, dedupe kept
  whichever arrived first, and both forks passed validation with byte-identical
  summaries.

Two conventions every contract shell here follows, for the same class of reason:

- MUST treat a zero-byte summary as "the peer has nothing". CBOR cannot parse an
  empty input, and returning an error there wedges the sync permanently.
- MUST provide an explicit empty-state seed path in the update path for any
  state with no `Default` — otherwise the first write to a fresh instance has
  nothing to merge into.
