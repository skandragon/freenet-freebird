# Freebird

Microblogging on [Freenet](https://freenet.org). No server: each author's feed
is a Freenet contract, reply discovery is a per-author inbox contract, and the
UI is a web app served from the network itself. Signup is anonymous (a locally
generated key); a [Ghost Key](https://freenet.org/ghostkey) buys a verified
check mark and the ability to reply into other people's threads.

**The trust rule:** your own feed is free; other people's attention costs a
Ghost Key.

Design: [`docs/superpowers/specs/2026-08-09-freebird-design.md`](docs/superpowers/specs/2026-08-09-freebird-design.md)

## Vocabulary

| Freebird | Meaning |
|---|---|
| **Peep** | A post (≤ 2 KB, signed, lives in your feed contract) |
| **Repeep** | A repost (not yet implemented) |
| **Reply** | A peep referencing another peep; discoverable via the target's inbox if you're verified |
| **Feed** | Your per-author contract: profile, follows, peeps, optional attestation |
| **Follower / Following** | Public follow list in your feed state |
| **Check mark** | Ghost Key attestation, verified by the contract itself |

## Layout

- `common/` — `freebird-core`: wire types, CRDT merge logic, ghostkey
  attestation verification, property tests
- `contracts/feed-contract/` — per-author feed (profile, follows, peeps,
  optional attestation)
- `contracts/inbox-contract/` — per-author reply inbox (ghostkey-gated writes)
- `contracts/cell-contract/` — FROZEN signed-cell kernel (owner-signed opaque
  state; never rebuild — see its crate docs)
- `control/` — `freebird-control`: control-channel schema (deployed build
  number + feature flags) carried in a cell body
- `tools/freebird-ctl/` — publisher CLI (`keygen`, `publish-control`, `show`)
- `delegates/freebird-delegate/` — per-app encrypted KV storage on the user's
  node (posting key, drafts)
- `ui/` — Dioxus web UI (`ui/contracts/` holds the compiled wasm the UI embeds
  for address derivation — refresh with `make contracts delegate`)
- `docs/` — engineering notes: reproducible/byte-frozen wasm builds,
  full-state validation cost analysis

## Build

```sh
make test        # workspace tests (CRDT proptests, attestation, delegate)
make contracts   # contract wasm + forbidden-import check (river#241 gate)
make delegate    # delegate wasm + import check
make ui          # dx release build (embeds the VENDORED wasm in ui/contracts/)
make publish     # site via fdev, then the control cell via freebird-ctl
                 # (needs node tunnel + ~/.freebird/publisher.key)
```

Requires: rustup stable + `wasm32-unknown-unknown`, `dx` (Dioxus CLI 0.7),
`fdev`, `wasm-tools`.

## License

AGPL-3.0-or-later
