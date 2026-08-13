# Freebird

Microblogging on [Freenet](https://freenet.org). No server: each author's feed
is a Freenet contract, reply discovery is a per-author inbox contract, and the
UI is a web app served from the network itself. Signup is anonymous (a locally
generated key) and anonymous accounts can do everything: peep, reply into
threads, get listed in Discover.

**The trust rule:** everyone writes; a [Ghost Key](https://freenet.org/ghostkey)
buys durability. Shared-write surfaces (reply inboxes, the directory) run a
two-tier slot policy — anonymous writers share a bounded pool and can be
crowded out under load, verified writers cannot. The check mark means
"durable, uncrowdable presence", not permission.

A Ghost Key is a paid, anonymous credential from freenet.org: the money funds
Freenet, and the mint is centrally operated (a master-key compromise could
issue unlimited check marks, and card rails can decline or geo-block).
Verification itself is not centralized — contracts verify the certificate
chain offline — and since attestation is optional, a dead mint costs
durability, not access.

Design: [`docs/superpowers/specs/2026-08-09-freebird-design.md`](docs/superpowers/specs/2026-08-09-freebird-design.md),
amended by [`2026-08-10-anonymous-parity.md`](docs/superpowers/specs/2026-08-10-anonymous-parity.md)
(the two-tier slot policy that replaced the ghostkey write gate)

## Vocabulary

| Freebird | Meaning |
|---|---|
| **Peep** | A post (≤ 2 KB, signed, lives in your feed contract) |
| **Repeep** | A repost (not yet implemented) |
| **Reply** | A peep referencing another peep; discoverable via the target's inbox |
| **Feed** | Your per-author contract: profile, follows, peeps, optional attestation |
| **Follower / Following** | Public follow list in your feed state |
| **Check mark** | Ghost Key attestation, verified by the contract itself; buys slot durability, not write access |

## Layout

- `common/` — `freebird-core`: wire types, CRDT merge logic, ghostkey
  attestation verification, property tests
- `contracts/feed-contract/` — per-author feed (profile, follows, peeps,
  optional attestation)
- `contracts/inbox-contract/` — per-author reply inbox (open writes, two-tier
  slot policy)
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
