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
registry paths, and the rustc sysroot). So the same source + same toolchain
yields *different* bytes on a different machine, which would spuriously rotate
addresses. The Docker build fixes the path leakage with a pinned toolchain
(`rust-toolchain.toml`), fixed `WORKDIR`/`CARGO_HOME`, and `--remap-path-prefix`
for all three path sources.

Path remapping is **not** sufficient for cross-arch bit-identity: an arm64 and
an amd64 build of the same source still differ (rustc/LLVM codegen is not
byte-identical across host arch). Rather than chase that, the build standardizes
on a single arch — **amd64** — matching CI and deployment. `make`'s `PLATFORM`
defaults to `linux/amd64`, so every Docker build targets amd64 regardless of
host.

## When a contract legitimately changes

1. `make build-docker` — rebuilds the four non-frozen contracts + delegate
   inside the pinned container (never the cell, never any `*_v1`) and vendors
   the reproducible bytes into `ui/contracts/`.
2. `make pin-hashes` — re-pin `scripts/wasm-hashes.txt`.
3. Update the golden addresses in `ui/src/keys.rs` for whatever rotated.
4. Add a dual-read window for the rotated contract so existing data stays
   reachable (see the `*_v1` precedent in `ui/src/keys.rs`).

## Proving reproducibility (amd64 build-of-record)

The requirement is that the build-of-record produces stable, verifiable bytes.
Because bytes are not bit-identical across host arch, that record is a single
arch — **amd64** — which is what CI and deployment run.

`scripts/repro-reference-hashes.txt` holds the canonical **amd64** sha256 of the
five non-frozen wasms for the CURRENT source. `make verify-repro` rebuilds in
the pinned amd64 container and checks against it. CI runs this on an amd64
runner (`docker-repro` job), so a green check proves the amd64 build reproduces
the pinned reference (run-to-run determinism of the build-of-record).

These reference hashes are **not** the vendored addressing bytes — those stay
grandfathered. The reference tracks the current source; when a contract's source
legitimately changes, refresh it on amd64 with `make repro-hashes` and paste the
output.

### Building on Apple Silicon

`rustc` for the amd64 target segfaults under qemu-user (arm64 host emulating
amd64), so you **cannot** produce the amd64 bytes locally on Apple Silicon. A
real contract rebuild (`make build-docker` → vendor → `pin-hashes` → goldens)
must therefore run on a native amd64 host or in CI, not on an M-series Mac. Use
the `docker-repro` CI job to verify. Everything else (`make test`, the UI build)
works fine on Apple Silicon; only the address-critical wasm build-of-record is
amd64-only.
