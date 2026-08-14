# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Always go through the Makefile — it addresses the pinned toolchain absolutely (Homebrew rust shadows rustup and lacks wasm32).

- `make test` — workspace tests. Not a plain `cargo test --workspace`: the UI, inbox-contract, and directory-contract must be tested in separate resolves or duplicate `#[no_mangle]` contract symbols break the link on Linux.
- `make lint` — clippy with `-D warnings`, same crate split as `test`. There is deliberately no `cargo fmt --check`: a release wasm embeds panic-location line numbers, so a formatting sweep over `contracts/` or `common/` can shift bytes and rotate addresses. Never run `cargo fmt` across this repo.
- `make ui` — Dioxus release build. Embeds the **vendored** wasm in `ui/contracts/`; it never rebuilds a contract.
- `make check-addresses` / `make check-legacy-wasm` / `make check-imports-vendored` — the CI gates; runnable offline.
- Single test: `cargo test -p <crate> <name>` (use the rustup toolchain, not Homebrew cargo).

## The one rule that matters: contract addresses are content-derived

Contract and delegate addresses derive from wasm bytes. If the bytes change, **every author's feed/inbox/avatar address rotates and the delegate key changes** — existing posts and stored posting keys become unreachable. A `common/` edit re-keys *everything*, including the delegate.

So: **do not run `make contracts`, `make delegate`, or `make build-docker` to "refresh" anything.** The committed bytes in `ui/contracts/` are the immutable source of truth. Rebuild only when a contract's source or `Cargo.lock` legitimately changed, and only as a deliberate rotation that also bumps the matching `*_GENERATION` constant in `ui/src/keys.rs`, adds a dual-read window, and has a migration story. `contracts/cell-contract` is FROZEN — never rebuild it.

Related invariants, each enforced by a Makefile target with a full explanation in its comment:

- `ui/contracts/*_v1.wasm` must be byte-identical to the build named in `scripts/live-build.txt` — not to generation 1. (`check-legacy-wasm`, issue #81)
- `LEGACY_DELEGATE_WASMS` in `ui/src/keys.rs` is cumulative — appending, never replacing, or old users lose their posting-key seed (issue #53).
- No wasm may import outside the `freenet_*` namespaces; a wasm-bindgen placeholder means the getrandom poison is back (freenet/river#241). Never enable a getrandom backend feature at the workspace level.
- After `make publish`, a follow-up PR must update `scripts/live-build.txt`, re-vendor the `_v1` blobs, `make pin-hashes`, and refresh the goldens in `ui/src/keys.rs`.

Never "fix" one of these checks by loosening it. They exist because each one has already cost users their data.

## Repo etiquette

- Branch and PR for every change; never commit to `main`. Branch names: `<feat|fix|refactor|infra|chore|research>/<kebab-name>`.
- Commit subjects are conventional-commit style and short: `fix: point the dual-read window at the live generation (#81)`, referencing the issue.
- The toolchain in `rust-toolchain.toml` is pinned because a rustc bump rotates addresses. Bump it deliberately.

## Reference

Repo knowledge lives in the `kb/` vault — start at `kb/index.md`, rules in
`kb/policy.md`. Files under `docs/` are stubs pointing there (they stay because
contract comments reference those paths, and editing a contract comment shifts
panic-location line numbers).

@kb/policies/reproducible-builds.md
@kb/specs/dual-read-window.md
