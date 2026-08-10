# Freebird

Microblogging on [Freenet](https://freenet.org). No server: each author's feed
is a Freenet contract, reply discovery is a per-author inbox contract, and the
UI is a web app served from the network itself. Signup is anonymous (a locally
generated key); a [Ghost Key](https://freenet.org/ghostkey) buys a verified
check mark and the ability to reply into other people's threads.

Design: [`docs/superpowers/specs/2026-08-09-freebird-design.md`](docs/superpowers/specs/2026-08-09-freebird-design.md)

## Layout

- `common/` — `freebird-core`: wire types, CRDT merge logic, ghostkey
  attestation verification, property tests
- `contracts/feed-contract/` — per-author feed (profile, follows, posts,
  optional attestation)
- `contracts/inbox-contract/` — per-author reply inbox (ghostkey-gated writes)
- `delegates/freebird-delegate/` — per-app encrypted KV storage on the user's
  node (posting key, drafts)
- `ui/` — Dioxus web UI

## License

AGPL-3.0-or-later
