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

Never rebuilt: `cell_contract.wasm` (the anchor/control/PoW kernel) and
every `*_v1.wasm` legacy blob. The cell kernel is frozen forever; the `_v1`
blobs are *copied* from the live build on each publish rather than compiled
— see `docs/dual-read-window.md` and `make check-legacy-wasm`.

The current `feed`/`avatar`/`inbox`/`directory`/`freebird_delegate` bytes are
**grandfathered** — they were built on macOS before the reproducible Docker
path existed. Each will migrate to reproducible Docker-built bytes the next time
it is legitimately rebuilt (see below), not before.

### Corollary: no whitespace-only churn in contract crates

`panic = 'abort'` still embeds `file:line` for every panic site, so a
formatting pass that shifts line numbers changes the wasm bytes — and with
them every derived address. Proven: `cargo fmt --all` on this repo rebuilt all
four non-frozen contracts to different hashes (the delegate happened to
survive). So `common/`, `contracts/`, `pow/` and `delegates/` are deliberately
left un-`rustfmt`ed; reformat them only as part of a change that is already
rotating those addresses. `ui/` and `tools/` compile into nothing
address-derived and are formatted normally. CI runs no fmt check, by design.

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
   the reproducible bytes into `ui/contracts/`. **It re-vendors all five**, so
   `git checkout` the wasms whose source did NOT change — vendoring a fresh
   build of an unchanged contract still rotates its address if its vendored
   bytes were grandfathered. (On Apple Silicon, build on a native amd64 host
   instead — see below.)
2. `make pin-hashes` — re-pin `scripts/wasm-hashes.txt`.
3. Update the line for the rotated contract in
   `scripts/repro-reference-hashes.txt` (leave the others — they must still
   match, which doubles as proof your build environment is canonical).
4. Update the golden addresses in `ui/src/keys.rs` for whatever rotated: run
   `cargo test -p freebird-ui golden_addresses_pinned`, take the new address
   from the failure output, and pin it with a comment recording the rotation.
5. Add a dual-read window so existing data stays reachable, and follow
   `docs/dual-read-window.md` — re-vendor the `_v1` blob from
   `scripts/live-build.txt`, mirror the outgoing wire types in
   `ui/src/legacy.rs`, regenerate its CBOR KATs, and run
   `make check-legacy-wasm`.

   The old "no-window precedent (#45/#49/#50/#51)… authors re-seat on their
   next republish" is RETRACTED (issue #81). Re-seating needs every listed
   author to return and every replier to repost, so in practice Discover
   went empty and threads lost their replies. Do not skip the window.

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
amd64), so `make build-docker` **cannot** produce the amd64 bytes locally on
Apple Silicon — and a `PLATFORM=linux/arm64` build runs fine but yields
different bytes for every crate (arch-dependent codegen), so its output must
never be vendored. Everything else (`make test`, the UI build) works fine on
Apple Silicon; only the address-critical wasm build-of-record is amd64-only.

The way out is any **native x86_64 Linux host** with rustup — no Docker
needed. The container only exists to fix the three embedded path sources, and
`--remap-path-prefix` does that just as well in a plain build (proven: the
unchanged crates reproduce their pinned reference hashes exactly):

```bash
# on the amd64 host, in a checkout of the branch
# (rust-toolchain.toml pulls the pinned toolchain + wasm32 target via rustup)
export PATH=$HOME/.cargo/bin:$PATH CARGO_HOME=$HOME/.cargo
RF="--remap-path-prefix=$PWD=/src \
    --remap-path-prefix=$CARGO_HOME=/cargo \
    --remap-path-prefix=$(rustc --print sysroot)=/rust"
RUSTFLAGS="$RF" cargo build --locked -p <changed-crate> \
    --target wasm32-unknown-unknown --release
sha256sum target/wasm32-unknown-unknown/release/*.wasm
```

This path is proven end to end: the #66 directory/inbox rotation (2026-08-13)
was built this way on the `freenet1` explorer node, and all three unchanged
crates reproduced their pinned reference hashes exactly. `make wasm-repro`
is the same target the container runs, so running it directly on an amd64
host is equivalent — it just needs `wasm-tools` at the version
`docker/Dockerfile` pins. See `docs/anon-pow-difficulty.md` for the worked
example.

**Always build the unchanged crates too and check their sha256 against
`scripts/repro-reference-hashes.txt` first** — a full match on the untouched
crates proves the environment is canonical; only then vendor the changed
crate's wasm (`scp` it into `ui/contracts/`, then `make check-imports
W=ui/contracts/<name>.wasm` and continue from `pin-hashes` above). The
`docker-repro` CI job is the final arbiter: it must stay green against the
refreshed reference hashes.
