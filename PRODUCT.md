# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: Freenet early adopters — people already running a node who want real
apps on the network; comfortable with keys, contracts, and tunnels. Secondary
(deliberate): privacy-seeking users leaving centralized social media; the UX
must stay clean enough that they never need to understand Freenet internals to
post, follow, and reply.

## Product Purpose

Freebird is a microblog that runs entirely on Freenet — no server, per-author
feed contracts, client-side aggregation, UI served from the network itself.
Success is genuine daily use: real people posting and staying, not just a
platform demo.

## Positioning

The trust rule no centralized competitor can copy: **your own feed is free;
other people's attention costs a Ghost Key.** Anonymous signup with a locally
generated key; a Ghost Key (one-time, anonymous, paid credential from
freenet.org) buys a verified check mark and the right to reply into other
people's threads. Spam resistance without identity, moderation without a
moderator.

## Operating Context

- Users run (or tunnel to) a Freenet node; the UI is a Dioxus wasm web app
  published to the network via `fdev`.
- Each author's feed is a Freenet contract (profile, follows, signed peeps,
  optional attestation); replies are discovered via a per-author inbox
  contract with ghostkey-gated writes.
- All aggregation (home feed merge, thread resolution) is client-side; the
  platform forbids contract-to-contract calls.
- A per-app encrypted delegate on the user's node stores the posting key and
  drafts; signup is instant and offline-local.
- Subscriptions are short leases (~2 min); unwatched contracts can rot.

## Capabilities and Constraints

- Peeps ≤ ~2 KB, signed; feed state capped (~200–500 posts, well under 1 MB
  practical PUT limit).
- Implemented: anonymous signup, posting, follows, client-side home feed,
  replies via inbox, check-mark attestation, profile page with danger zone,
  auto/light/dark theme.
- Not yet implemented: repeeps, likes, media, mentions/notifications, global
  discovery, private follows.
- Design spec: `docs/superpowers/specs/2026-08-09-freebird-design.md`.
- Stack: Rust + Dioxus 0.7 web (`ui/`), contracts and delegate in wasm.

## Brand Commitments

- The name **Freebird** is locked.
- The peep/repeep bird vocabulary is current copy but explicitly flexible —
  it may change if better wording emerges; do not treat it as immovable.
- License AGPL-3.0-or-later.

## Evidence on Hand

- Working product screenshot: `freebird-live.png` (repo root).
- Real, verifiable mechanism claims (contract-enforced attestation, signed
  posts) — demonstrable, not marketing copy.
- No testimonials, user counts, or press; future surfaces must not invent
  any.

## Product Principles

1. **Adopters first, normies always welcome** — never require Freenet
   knowledge for the core loop (post, follow, reply), but never hide the
   mechanism from those who want it.
2. **The trust rule is the product** — every shared-write surface is
   ghostkey-gated; free self-expression, paid access to others' attention.
3. **No server, ever** — no feature may quietly reintroduce a central
   service; client-side aggregation is the architecture, not a limitation.
4. **Daily-use bar** — judged as a real microblog (speed, clarity, habit),
   not as a tech demo.
5. **Honest by construction** — claims the contract can verify beat claims
   the UI asserts.
