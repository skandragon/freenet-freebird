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
WASM_DIR := target/$(WASM_TARGET)/release

.PHONY: all contracts delegate ui test check-imports check-imports-vendored check-addresses check-built pin-hashes publish clean

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
# committed bytes are the source of truth, because compiled bytes are not
# reproducible across toolchains and any byte change rotates every derived
# address. `make contracts`/`make delegate` are the deliberate acts that
# refresh them (guarded by check-addresses); the ui build never does.
ui:
	$(MAKE) check-addresses
	cd ui && $(DX) build --release

# The UI tests build separately: a joint --workspace build feature-unifies the
# contract crates (default features re-enable their #[no_mangle] entry points)
# and the UI test binary then links several contract rlibs with identical
# symbols — linux lld rejects the duplicates (macOS ld64 happens to tolerate).
test:
	$(CARGO) test --workspace --exclude freebird-ui --locked
	$(CARGO) test -p freebird-ui --locked

# Site first, then the control cell: the advertised build must never get
# ahead of the bundle users can actually load.
publish:
	scripts/publish-ui.sh
	$(CARGO) run --locked -p freebird-ctl --release -- publish-control \
	  --build $$(git rev-list --count HEAD) \
	  --label $$(git rev-parse --short HEAD)

clean:
	$(CARGO) clean
