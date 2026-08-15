---
type: policy
title: Testing, linting, and the CI gates
description: Why the test and lint runs are split across three cargo resolves instead of one workspace build, what each CI job proves, and why there is deliberately no formatting check.
timestamp: 2026-08-14T00:00:00Z
covers:
  - Makefile
  - .github/workflows/ci.yml
  - ui/src/fixtures.rs
---

## The three-resolve split

Neither `make test` nor `make lint` is a single `--workspace` invocation, and
both split the same way. A joint resolve feature-unifies the contract crates,
which re-enables their default features — and with them the `#[no_mangle]`
contract entry points. The UI test binary then links several contract rlibs
exporting identical symbols, and lld rejects the duplicates. macOS happens to
tolerate it, so this fails only on Linux and only in CI.

The inbox and directory crates are split out for a second instance of the same
problem: both link the cell contract for the PoW difficulty type, and a joint
resolve unifies the cell contract's own entry points into their cdylibs. Testing
them in an isolated resolve keeps the cell contract a default-features-off
dependency, so nothing duplicates. [#51]

## CI jobs and what each proves

- `vendored-wasm` — address stability and forbidden imports against the
  *committed* bytes, with no Rust build at all. Needs full git history, because
  the legacy-blob check reads the live build's blobs out of the object store.
- `test` — the three-resolve test run.
- `docker-repro` — rebuilds the five non-frozen wasms in the pinned amd64
  container and asserts the reference hashes. It does not diff the grandfathered
  vendored bytes, so it can never force a rotation.
- `lint` — clippy with warnings denied, same three-resolve split.

## Legacy fixtures: pinning the mirror to the old contract's behavior

`ui/src/legacy.rs` mirrors the wire types of the build in
`scripts/live-build.txt`. Every test in that module signs with the mirror and
verifies with the mirror, so it passes for any self-consistent shape; the
wire-format KATs are what pin the shape. Neither pins the *behavior* the
deployed contract enforces — whether it accepts a record we would build, or
merges a stream of deltas the way our `merge` does.

`ui/fixtures/` closes that. `make fixtures` drives the ACTUAL vendored
`*_v1.wasm` on a node: PUT a seed state, send deltas built from the mirror
types, capture what the old contract merged. The committed bytes are therefore
bytes the deployed contract validated and wrote, and the two decode tests run
against them with no node, in CI. Both are load-bearing — verified by mutation:
renaming a mirrored field fails the decode test, and inverting the LWW
comparison in `merge` fails only the semantics test.

MUST regenerate against an **isolated local node**, never the 7509 tunnel. The
legacy directory is one global address for the whole network, so synthetic
listings PUT through the live node land in every user's Discover. See the
`local-dev` skill; `make fixtures` defaults to port 7511 for that reason.

The corpus is synthetic and deterministic — authors are seed bytes, times are
literals — so it carries no live user data and regenerates byte-identically.

Attested records are deliberately absent. `AttestationV1::verify` takes a
`master_override` that contracts pass as `None`, so the deployed wasm anchors
on ghostkey_lib's compiled-in Freenet master; a chain minted by
`freebird-core`'s `test-fixtures` feature verifies only under an override the
real bytes never take. Building a test-master variant of the old contract would
produce different bytes and stop being the old contract. The attested paths
stay on the unit tests that can pass an override.

## No formatting check, deliberately

Release wasm embeds `file:line` panic locations, so a formatting pass that
shifts line numbers changes the bytes and rotates every derived address. This is
proven, not theoretical: a whole-repo `cargo fmt` rebuilt all four non-frozen
contracts to different hashes.

MUST NOT run a formatter across `common/`, `contracts/`, `pow/`, or
`delegates/`. Those trees are deliberately un-formatted; reformat them only
inside a change that is already rotating those addresses. The UI and tools crates
compile into nothing address-derived and are formatted normally. See
[reproducible builds](reproducible-builds.md).

## Forbidden imports

Every wasm is checked for imports outside the Freenet host namespaces. A
wasm-bindgen placeholder import means a random-number backend has been enabled
somewhere in the dependency graph, and the module will not instantiate under the
host runtime at all. MUST NOT enable a `getrandom` backend feature at the
workspace level; crates compiling the Ghost Key library to wasm declare their own
dependency with a custom backend and register nothing, because the verification
paths call no RNG.
