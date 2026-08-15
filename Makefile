# Freebird build tooling.
# Homebrew rust shadows the rustup toolchain and lacks the wasm32 target, and
# apple's make 3.81 ignores exported PATH on its direct-exec fast path — so
# tools are addressed absolutely.
TOOLCHAIN := $(shell sed -n 's/^channel = "\(.*\)"$$/\1/p' rust-toolchain.toml)
RUSTUP_BIN := $(HOME)/.rustup/toolchains/$(TOOLCHAIN)-aarch64-apple-darwin/bin
# Fall back to the rustup shim (which honors rust-toolchain.toml) when the
# pinned toolchain dir doesn't exist — e.g. Linux CI or first build.
CARGO := $(firstword $(wildcard $(RUSTUP_BIN)/cargo) $(wildcard $(HOME)/.cargo/bin/cargo) cargo)
DX := $(HOME)/.cargo/bin/dx
# wasm-tools may come from cargo or homebrew; a missing binary must FAIL the
# import check, not silently pass it (grep of no output looks "clean").
WASM_TOOLS := $(shell command -v wasm-tools || command -v $(HOME)/.cargo/bin/wasm-tools || echo /opt/homebrew/bin/wasm-tools)
# dx shells out to cargo/rustc — give it the right toolchain first.
export PATH := $(RUSTUP_BIN):$(HOME)/.cargo/bin:$(PATH)

WASM_TARGET := wasm32-unknown-unknown
# Honor CARGO_TARGET_DIR (the Docker build points it outside the mount).
CARGO_TARGET := $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)
WASM_DIR := $(CARGO_TARGET)/$(WASM_TARGET)/release

# Non-frozen contract + delegate wasm rebuilt by the reproducible Docker path.
# Excludes the FROZEN cell_contract and every *_v1 legacy blob on purpose.
REPRO_WASMS := feed_contract.wasm avatar_contract.wasm directory_contract.wasm inbox_contract.wasm freebird_delegate.wasm
DOCKER_IMG := freebird-repro-build
# Build-of-record arch. wasm bytes are NOT bit-identical across host arch
# (rustc/LLVM codegen differs arm64 vs amd64 even with paths remapped), so the
# reproducible build standardizes on amd64 — native on CI, emulated on Apple
# Silicon. Override only to experiment; the vendored/reference bytes are amd64.
PLATFORM ?= linux/amd64
PLATFORM_ARG := $(if $(PLATFORM),--platform $(PLATFORM),)
DOCKER_RUN := docker run --rm $(PLATFORM_ARG) -u $$(id -u):$$(id -g) -v $(CURDIR):/build -w /build -e CARGO_TARGET_DIR=/tmp/target $(DOCKER_IMG)

.PHONY: all contracts delegate ui test lint check-imports check-imports-vendored check-addresses check-built check-legacy-wasm check-site-staged pin-hashes publish clean wasm-repro build-docker-image build-docker repro-hashes verify-repro

all: test contracts delegate ui

contracts:
	$(CARGO) build --locked -p feed-contract -p avatar-contract --target $(WASM_TARGET) --release
	# directory-contract and inbox-contract build in their own invocations:
	# joint feature unification with the pinned contracts could alter their
	# bytes (inbox v2 pulls deps feed/avatar must never unify with).
	$(CARGO) build --locked -p directory-contract --target $(WASM_TARGET) --release
	$(CARGO) build --locked -p inbox-contract --target $(WASM_TARGET) --release
	# cell-contract likewise — and it is the FROZEN kernel: its vendored wasm
	# must never change bytes again (see contracts/cell-contract/src/lib.rs).
	$(CARGO) build --locked -p cell-contract --target $(WASM_TARGET) --release
	$(MAKE) check-imports W=$(WASM_DIR)/feed_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/inbox_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/avatar_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/directory_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/cell_contract.wasm
	$(MAKE) check-built BUILT="feed_contract.wasm inbox_contract.wasm avatar_contract.wasm directory_contract.wasm cell_contract.wasm"
	cp $(WASM_DIR)/feed_contract.wasm $(WASM_DIR)/inbox_contract.wasm $(WASM_DIR)/avatar_contract.wasm $(WASM_DIR)/directory_contract.wasm $(WASM_DIR)/cell_contract.wasm ui/contracts/
	$(MAKE) check-addresses

delegate:
	$(CARGO) build --locked -p freebird-delegate --target $(WASM_TARGET) --release
	$(MAKE) check-imports W=$(WASM_DIR)/freebird_delegate.wasm
	$(MAKE) check-built BUILT=freebird_delegate.wasm
	cp $(WASM_DIR)/freebird_delegate.wasm ui/contracts/
	$(MAKE) check-addresses

# Contract/delegate addresses are content-derived: if these bytes change, every
# author's feed/inbox/avatar address rotates and the delegate key changes —
# existing posts and stored posting keys become unreachable to the new build
# (the 2026-08-10 avatar release did this by accident: adding a module to
# freebird-core changed ALL contract bytes). Rotation must be a deliberate,
# reviewed act with a migration story — never a rebuild side effect.
check-addresses:
	@shasum -a 256 -c scripts/wasm-hashes.txt >/dev/null 2>&1 || { \
	  echo "ERROR: contract wasm bytes changed — all derived addresses will ROTATE"; \
	  echo "and old posts / stored posting keys become unreachable."; \
	  echo "If this rotation is intentional (with a migration plan), re-pin:"; \
	  echo "  make pin-hashes"; \
	  shasum -a 256 -c scripts/wasm-hashes.txt 2>/dev/null | grep -v ': OK$$'; \
	  exit 1; }
	@echo "contract addresses stable"

pin-hashes:
	shasum -a 256 ui/contracts/*.wasm > scripts/wasm-hashes.txt

# The dual-read window derives its legacy addresses from the *_v1 blobs, so
# each one must be the bytes of the build currently serving users — NOT of
# generation 1 (issue #81: inbox and directory were pinned a generation
# behind the live build, so the window read contracts nobody had written to,
# and every returning user lost their Discover listing and their replies).
#
# The live commit is recorded in scripts/live-build.txt and its blobs come
# straight out of git, so this is an offline, deterministic check.
#
# freebird_delegate_v1.wasm is deliberately NOT here. The delegate has no
# dual-read window: LEGACY_DELEGATE_WASMS (ui/src/keys.rs) is a CUMULATIVE
# registry of every generation ever shipped, because the startup probe folds
# each old generation's stored posting-key seed forward (issue #53).
# Requiring it to equal the live build would overwrite the oldest entry and
# destroy the seed of anyone still on that generation.
LEGACY_ROLES := feed_contract inbox_contract avatar_contract directory_contract
check-legacy-wasm:
	@live=$$(grep -v '^#' scripts/live-build.txt | tr -d '[:space:]'); \
	[ -n "$$live" ] || { echo "ERROR: scripts/live-build.txt names no commit"; exit 1; }; \
	git cat-file -e "$$live^{commit}" 2>/dev/null || { \
	  echo "ERROR: live build $$live is not in this repo — CI needs full history"; exit 1; }; \
	git merge-base --is-ancestor "$$live" HEAD || { \
	  echo "ERROR: live build $$live is not an ancestor of HEAD."; \
	  echo "A commit that was never merged cannot be what users are running."; \
	  exit 1; }; \
	fail=0; \
	for r in $(LEGACY_ROLES); do \
	  v1="ui/contracts/$${r}_v1.wasm"; \
	  git cat-file -e "$$live:ui/contracts/$$r.wasm" 2>/dev/null || { \
	    echo "ERROR: $$r.wasm absent from live build $$live"; fail=1; continue; }; \
	  [ -s "$$v1" ] || { echo "ERROR: $$v1 is missing or EMPTY"; fail=1; continue; }; \
	  want=$$(git cat-file blob "$$live:ui/contracts/$$r.wasm" | shasum -a 256 | cut -d' ' -f1); \
	  got=$$(shasum -a 256 "$$v1" | cut -d' ' -f1); \
	  [ "$$want" = "$$got" ] || { \
	    echo "ERROR: $$v1 is NOT the live build's bytes"; \
	    echo "  live ($$live): $$want"; \
	    echo "  vendored _v1:  $$got"; \
	    fail=1; }; \
	done; \
	for f in ui/contracts/*_v1.wasm; do \
	  r=$$(basename "$$f" _v1.wasm); \
	  case " $(LEGACY_ROLES) freebird_delegate " in \
	    *" $$r "*) ;; \
	    *) echo "ERROR: $$f is vendored but no rule covers it — add it to"; \
	       echo "       LEGACY_ROLES, or document why it is exempt."; fail=1;; \
	  esac; \
	done; \
	[ $$fail -eq 0 ] || { \
	  echo ""; \
	  echo "The dual-read window would read a contract nobody writes to (issue #81)."; \
	  echo "Re-vendor from the live build (write to a temp file first — a shell"; \
	  echo "redirect truncates the target BEFORE git runs, and a 0-byte blob is"; \
	  echo "how this check used to be fooled):"; \
	  echo "  git cat-file blob $$live:ui/contracts/<role>.wasm > /tmp/<role>.wasm"; \
	  echo "  mv /tmp/<role>.wasm ui/contracts/<role>_v1.wasm"; \
	  echo "then: make pin-hashes, and update the goldens in ui/src/keys.rs."; \
	  exit 1; }
	@echo "legacy _v1 wasm matches the live build"

# Verify freshly built wasm ($(BUILT), basenames in $(WASM_DIR)) against the
# pinned hashes BEFORE it reaches ui/contracts/ — a failed build must leave
# the vendored dir byte-identical to what it was.
check-built:
	@m=$$(for w in $(BUILT); do grep -F "ui/contracts/$$w" scripts/wasm-hashes.txt; done \
	  | sed 's|ui/contracts/|$(WASM_DIR)/|'); \
	[ $$(echo "$$m" | grep -c .) -eq $$(echo "$(BUILT)" | wc -w) ] || { \
	  echo "ERROR: not every built wasm is pinned in scripts/wasm-hashes.txt"; exit 1; }; \
	echo "$$m" | shasum -a 256 -c >/dev/null 2>&1 || { \
	  echo "ERROR: built wasm differs from pinned — all derived addresses will ROTATE"; \
	  echo "and old posts / stored posting keys become unreachable."; \
	  echo "ui/contracts/ was left untouched. If this rotation is intentional"; \
	  echo "(with a migration plan), copy the rotated wasm from $(WASM_DIR)/"; \
	  echo "into ui/contracts/ and run: make pin-hashes"; \
	  echo "$$m" | shasum -a 256 -c 2>/dev/null | grep -v ': OK$$'; \
	  exit 1; }
	@echo "built wasm matches pinned addresses"

# Fail if a wasm imports anything outside the freenet host namespaces —
# a wasm-bindgen placeholder import means the getrandom poison is back
# (freenet/river#241) and the module will not instantiate under wasmtime.
check-imports:
	@[ -x "$(WASM_TOOLS)" ] || { echo "wasm-tools not found: $(WASM_TOOLS)"; exit 1; }
	@bad=$$($(WASM_TOOLS) print $(W) | grep '(import' | grep -v '"freenet_' || true); \
	if [ -n "$$bad" ]; then echo "FORBIDDEN IMPORTS in $(W):"; echo "$$bad"; exit 1; fi
	@echo "$(W): imports clean"

# Same check against the committed bytes the UI actually ships — what CI runs.
check-imports-vendored:
	@for w in ui/contracts/*.wasm; do \
	  $(MAKE) --no-print-directory check-imports W=$$w || exit 1; \
	done

# The UI embeds the VENDORED wasm in ui/contracts/ (include_bytes) — the
# committed bytes are the IMMUTABLE source of truth. A plain host build is NOT
# byte-reproducible (rustc bakes in absolute paths), so when a contract must be
# rebuilt it is done reproducibly via Docker (see wasm-repro / build-docker and
# docs/reproducible-builds.md). Any byte change rotates every derived address,
# so rebuilding (`make build-docker`, or the frozen-cell-inclusive
# `make contracts`/`make delegate`) is a deliberate, reviewed act guarded by
# check-addresses — done only when a contract's source or Cargo.lock actually
# changes; the ui build never does.
#
# The output dir is wiped first: dx hashes each bundle into its filename and
# never removes the previous one, and publish-ui.sh ships the directory
# wholesale — so every stale build's 2-4MB wasm rode along inside the website
# contract (issue #83: 62 files / 3.6MB vs 3 files / 735KB). Only the bundle
# named in index.html is ever fetched; the rest is freight every hosting node
# stores and every first-time visitor waits on. The cost is re-emitting the
# assets each build, which is nothing next to the wasm compile.
UI_SITE_DIR := $(CARGO_TARGET)/dx/freebird-ui/release/web/public
ui:
	$(MAKE) check-addresses
	rm -rf $(UI_SITE_DIR)
	cd ui && $(DX) build --release
	$(MAKE) check-site-staged

# Backstop for the wipe above: the staged site must carry exactly one app
# bundle. If this ever fires, something republished into a dirty output dir
# and the extra megabytes would go on the network permanently.
check-site-staged:
	@n=$$(ls $(UI_SITE_DIR)/assets/*_bg-*.wasm 2>/dev/null | wc -l | tr -d ' '); \
	  [ "$$n" = 1 ] || { \
	    echo "ERROR: $$n app wasm bundles staged in $(UI_SITE_DIR) (expected 1)."; \
	    echo "Stale bundles ship inside the website contract — see issue #83."; \
	    echo "Fix: rm -rf $(UI_SITE_DIR) && make ui"; \
	    exit 1; }
	@echo "site staged: one app bundle, $$(du -sh $(UI_SITE_DIR) | cut -f1)"

# The UI tests build separately: a joint --workspace build feature-unifies the
# contract crates (default features re-enable their #[no_mangle] entry points)
# and the UI test binary then links several contract rlibs with identical
# symbols — linux lld rejects the duplicates (macOS ld64 happens to tolerate).
#
# inbox-contract and directory-contract are split out for the SAME reason
# (issue #51): they link cell-contract for the PoW difficulty type, and a joint
# --workspace build unifies cell-contract's default freenet-main-contract entry
# points into their own cdylibs. Testing them in an isolated resolve keeps
# cell-contract a df=false dependency (no entry points), so nothing duplicates.
test:
	$(CARGO) test --workspace --exclude freebird-ui --exclude inbox-contract --exclude directory-contract --locked
	$(CARGO) test -p inbox-contract -p directory-contract --locked
	$(CARGO) test -p freebird-ui --locked

# Clippy only — deliberately NO `cargo fmt --check`. rustfmt would rewrite
# contract sources, and a release wasm embeds panic-location line numbers, so
# a formatting sweep can shift bytes and rotate every derived address. Format
# by hand, locally, and never across contracts/ or common/.
#
# Split the same way as `test`: a joint --workspace resolve unifies the
# contract crates' default features and duplicates their entry-point symbols.
lint:
	$(CARGO) clippy --workspace --exclude freebird-ui --exclude inbox-contract --exclude directory-contract --all-targets --locked -- -D warnings
	$(CARGO) clippy -p inbox-contract -p directory-contract --all-targets --locked -- -D warnings
	$(CARGO) clippy -p freebird-ui --all-targets --locked -- -D warnings

# Site first, then the control cell: the advertised build must never get
# ahead of the bundle users can actually load.
publish: check-legacy-wasm
	scripts/publish-ui.sh
	$(CARGO) run --locked -p freebird-ctl --release -- publish-control \
	  --build $$(git rev-list --count HEAD) \
	  --label $$(git rev-parse --short HEAD)
	@echo ""
	@echo "PUBLISHED $$(git rev-parse --short HEAD). This commit is now the live"
	@echo "build, so the NEXT release's dual-read window must read ITS contracts."
	@echo "Open a follow-up PR that:"
	@echo "  1. writes $$(git rev-parse --short HEAD) into scripts/live-build.txt"
	@echo "  2. re-vendors each ui/contracts/<role>_v1.wasm from it"
	@echo "  3. runs make pin-hashes and updates the goldens in ui/src/keys.rs"
	@echo "Skipping this is issue #81."

# --- Reproducible Docker build of the non-frozen contract + delegate wasm ---
#
# Contract/delegate addresses are content-derived from wasm bytes. rustc bakes
# absolute paths (source dir, CARGO_HOME, and the rustc sysroot whose triple
# differs arm64 vs amd64) into the module, so a plain build is NOT reproducible
# across machines. Running inside the pinned Docker image with --remap-path-prefix
# maps all three to fixed tokens, making the bytes host/arch-independent.
#
# wasm-repro runs INSIDE the container. It builds ONLY the four non-frozen
# contracts + the delegate — never the frozen cell-contract, never any *_v1
# blob — then copies the results onto the mount for the host to pick up.
wasm-repro:
	@RF="--remap-path-prefix=$(CURDIR)=/src --remap-path-prefix=$${CARGO_HOME}=/cargo --remap-path-prefix=$$(rustc --print sysroot)=/rust"; \
	set -e; \
	RUSTFLAGS="$$RF" $(CARGO) build --locked -p feed-contract -p avatar-contract --target $(WASM_TARGET) --release; \
	RUSTFLAGS="$$RF" $(CARGO) build --locked -p directory-contract --target $(WASM_TARGET) --release; \
	RUSTFLAGS="$$RF" $(CARGO) build --locked -p inbox-contract --target $(WASM_TARGET) --release; \
	RUSTFLAGS="$$RF" $(CARGO) build --locked -p freebird-delegate --target $(WASM_TARGET) --release
	$(MAKE) check-imports W=$(WASM_DIR)/feed_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/inbox_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/avatar_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/directory_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/freebird_delegate.wasm
	mkdir -p $(CURDIR)/target/repro
	cp $(addprefix $(WASM_DIR)/,$(REPRO_WASMS)) $(CURDIR)/target/repro/

build-docker-image:
	docker build $(PLATFORM_ARG) -t $(DOCKER_IMG) -f docker/Dockerfile .

# Reproducible build then print the sha256 of the 5 non-frozen wasm. Use with
# PLATFORM=linux/amd64 to compare arch-to-arch.
repro-hashes: build-docker-image
	$(DOCKER_RUN) make wasm-repro
	@shasum -a 256 $(addprefix $(CURDIR)/target/repro/,$(REPRO_WASMS))

# Run ONLY when a contract legitimately changes (source or Cargo.lock edit that
# alters its bytes). Refreshes the vendored non-frozen wasm from a reproducible
# build; this is a deliberate rotation, so follow with `make pin-hashes`, update
# the goldens in ui/src/keys.rs, and add dual-read for the rotated contract.
# Cell + *_v1 blobs are never rebuilt. Do NOT run this as a routine step: the
# vendored bytes are the immutable source of truth (see docs/reproducible-builds.md).
build-docker: build-docker-image
	$(DOCKER_RUN) make wasm-repro
	cp $(addprefix $(CURDIR)/target/repro/,$(REPRO_WASMS)) ui/contracts/

# Reproducibility gate: build in the pinned amd64 container and assert the four
# non-frozen contracts + delegate match scripts/repro-reference-hashes.txt
# (canonical amd64 hashes of the CURRENT source). wasm bytes are NOT bit-
# identical across host arch, so amd64 is the single build-of-record; CI runs
# this on amd64 and a pass proves the amd64 build is deterministic against the
# pinned reference. It does NOT diff the grandfathered vendored addressing bytes,
# so it never forces a rotation. When a contract's source legitimately changes,
# refresh the reference on amd64: `make repro-hashes` then paste into the file.
verify-repro: build-docker-image
	$(DOCKER_RUN) make wasm-repro
	@shasum -a 256 $(addprefix $(CURDIR)/target/repro/,$(REPRO_WASMS))
	shasum -a 256 -c scripts/repro-reference-hashes.txt

clean:
	$(CARGO) clean
