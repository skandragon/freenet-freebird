# Reproducible contract & delegate builds

## Policy: vendored wasm is the immutable source of truth

The wasm in `ui/contracts/` is embedded into the UI with `include_bytes!`. A
contract/delegate address is derived from its wasm bytes, so **any byte change
rotates every derived address** — feed/inbox/avatar/directory addresses and the
delegate key — making existing posts and stored posting keys unreachable to the
new build.

Therefore the committed vendored bytes are frozen. We do **not** regenerate or
re-pin them as a routine step. We rebuild + re-pin **only** when a contract's
inputs actually change: its source, or a dependency/`Cargo.lock` bump that
alters its bytes.

Frozen forever (never rebuilt): `cell_contract.wasm` (the anchor/control/PoW
kernel) and every `*_v1.wasm` legacy blob.

The current `feed`/`avatar`/`inbox`/`directory`/`freebird_delegate` bytes are
**grandfathered** — they were built on macOS before the reproducible Docker
path existed. Each will migrate to reproducible Docker-built bytes the next time
it is legitimately rebuilt (see below), not before.

## Why a plain build is not reproducible

`rustc` bakes absolute paths into the wasm (the source dir, `CARGO_HOME`
registry paths, and the rustc sysroot — whose triple differs between arm64 and
amd64). So the same source + same toolchain yields *different* bytes on a
different machine, which would spuriously rotate addresses. The Docker build
fixes this with a pinned toolchain (`rust-toolchain.toml`), fixed
`WORKDIR`/`CARGO_HOME`, and `--remap-path-prefix` for all three path sources.

## When a contract legitimately changes

1. `make build-docker` — rebuilds the four non-frozen contracts + delegate
   inside the pinned container (never the cell, never any `*_v1`) and vendors
   the reproducible bytes into `ui/contracts/`.
2. `make pin-hashes` — re-pin `scripts/wasm-hashes.txt`.
3. Update the golden addresses in `ui/src/keys.rs` for whatever rotated.
4. Add a dual-read window for the rotated contract so existing data stays
   reachable (see the `*_v1` precedent in `ui/src/keys.rs`).

## Proving reproducibility

`make repro-check` builds twice from clean in the container and asserts the
wasm is byte-identical run-to-run. It runs in CI (`docker-repro` job). It does
**not** diff against the vendored bytes, so it never forces a rotation of the
grandfathered blobs.
