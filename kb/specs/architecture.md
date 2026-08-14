---
type: spec
title: System architecture
description: How Freebird is put together — per-author feed and inbox contracts, a global directory, the frozen cell kernel, a KV delegate for the posting key, and a wasm UI doing all aggregation client-side. Includes the platform constraints that force that shape, for anyone building a new surface on it.
timestamp: 2026-08-14T00:00:00Z
status: living
covers:
  - common/src/**
  - contracts/**
  - delegates/**
  - control/**
  - anchor/**
  - ui/src/**
---

Start here before adding a surface. The shape below is not a preference — most
of it is forced by what a Freenet contract can and cannot do, and the
constraints section says which.

## The pieces

- **Feed contract**, one instance per author. Profile, public follow list, a
  capped log of signed peeps, and an optional Ghost Key attestation. The author
  is the only writer.
- **Inbox contract**, one instance per author. Reply pointers written by *other*
  people, under a two-tier slot policy — see
  [the trust rule](../product/trust-rule.md). This is what makes replies
  discoverable at all, since a contract cannot look at another contract.
- **Directory contract**, one global instance. Listings for Discover, also
  two-tier. A doorbell: authors write a small row announcing themselves, and
  clients fetch the real thing from the address the row names.
- **Cell contract**, one frozen kernel serving many cells keyed by
  `{owner, purpose}`. Carries the control channel and the PoW bar. See
  [the cell contract](cell-contract.md).
- **Delegate**, per-app encrypted key-value storage on the user's own node.
  Holds the posting key seed and drafts. Signup writes here and nowhere else,
  which is why it is instant and works offline.
- **UI**, a wasm web app published to the network and served from it. Does every
  merge, thread resolution, and follow expansion client-side.

## Constraints that force this shape

- **No contract-to-contract calls.** A contract cannot read another contract's
  state, so anything resembling a join happens in the client. This is why
  replies live in a per-author inbox rather than being looked up from the feed,
  and why the home feed is assembled by fetching each followed author's feed
  and merging locally.
- **No cross-call memory.** The runtime creates a fresh wasm instance per call
  and drops it after, so nothing can be cached between calls — see
  [full-state validate_state cost](validate-state-cost.md) for what that costs
  in practice.
- **State size drives failure, not a hard limit.** The nominal cap is tens of
  megabytes; the practical target is about one megabyte, past which write
  failures climb steeply. Peeps are capped at ~2 KB and a feed at a few hundred
  posts to stay well inside that.
- **Subscription is a short lease, not a pin.** An unwatched contract rots.
  Anything that assumes a contract stays resident because it was once published
  is wrong.
- **Addresses derive from wasm bytes.** Every structural change is therefore a
  migration problem before it is a feature — see
  [address derivation](address-derivation.md) and
  [the dual-read window](dual-read-window.md).
- **Contracts get a host clock but do no I/O.** Time-based rules are possible;
  fetching anything is not.

## Adding a surface

The questions that decide the design, in order:

1. Who writes it? A single-author surface can be a new field on the feed
   contract and costs a feed rotation. A shared-write surface needs its own
   contract, a slot policy, and a PoW tier.
2. Does it need to be discovered, or is its address derivable? Derivable
   addresses cost nothing; discovery needs a doorbell row somewhere.
3. What merges when two peers disagree? Answer this with the
   [CRDT merge rules](crdt-merge-rules.md) in hand — every one of them exists
   because it was gotten wrong once.
4. Does it change contract bytes? If yes, it is a rotation: generation bump,
   dual-read window, legacy wire types mirrored in the UI crate. Budget for that
   before starting, not after.

A surface that needs schema freedom without rotation should ride the cell
kernel instead of getting its own contract — that is what the opaque body is
for.

River, the Freenet group-chat app, is the pattern source worth reading before
inventing anything: retention horizons, canonical summaries, scaffold
composition, and the chat delegate's key-value storage all came from there.

## Where the code lives

The workspace splits along those pieces: shared wire types and merge logic in
`common/`, one crate per contract under `contracts/`, the delegate under
`delegates/`, the control-channel schema in `control/`, the publisher CLI in
`tools/`, and the UI in `ui/` — which also vendors the compiled wasm it embeds
for address derivation. Note that legacy wire types live in the UI crate on
purpose: a legacy module inside a contract crate compiles into that contract and
rotates its address.
