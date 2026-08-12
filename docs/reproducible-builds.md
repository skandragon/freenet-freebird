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

## Proving reproducibility (cross-arch)

The real requirement is that an arm64 dev machine and the amd64 CI/deploy
environment produce **identical** wasm (hence identical addresses).

`scripts/repro-reference-hashes.txt` holds the canonical sha256 of the five
non-frozen wasms for the CURRENT source, produced by the reproducible Docker
build and pinned on arm64. `make verify-repro` rebuilds in the container and
checks against it. CI runs this on an **amd64** runner (`docker-repro` job), so
a green check is a live proof that arm64 == amd64.

These reference hashes are **not** the vendored addressing bytes — those stay
grandfathered. The reference tracks the current source; when a contract's source
legitimately changes, refresh it with `make repro-hashes` and paste the output.

### Note on emulation

`rustc` for the amd64 target segfaults under qemu-user (arm64 host emulating
amd64), so you cannot reliably reproduce amd64 bytes locally on Apple Silicon —
use the amd64 CI job as the cross-arch check. The build-of-record is the amd64
image (CI and deployment are amd64); the reference hashes are the amd64 result,
which the arm64 build matches natively.
