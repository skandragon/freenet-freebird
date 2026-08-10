# Freebird build tooling.
# Homebrew rust shadows the rustup toolchain and lacks the wasm32 target, and
# apple's make 3.81 ignores exported PATH on its direct-exec fast path — so
# tools are addressed absolutely.
RUSTUP_BIN := $(HOME)/.rustup/toolchains/stable-aarch64-apple-darwin/bin
CARGO := $(RUSTUP_BIN)/cargo
DX := $(HOME)/.cargo/bin/dx
WASM_TOOLS := $(HOME)/.cargo/bin/wasm-tools
# dx shells out to cargo/rustc — give it the right toolchain first.
export PATH := $(RUSTUP_BIN):$(HOME)/.cargo/bin:$(PATH)

WASM_TARGET := wasm32-unknown-unknown
WASM_DIR := target/$(WASM_TARGET)/release

.PHONY: all contracts delegate ui test check-imports check-addresses pin-hashes publish clean

all: test contracts delegate ui

contracts:
	$(CARGO) build -p feed-contract -p inbox-contract -p avatar-contract --target $(WASM_TARGET) --release
	# directory-contract builds in its own invocation: joint feature
	# unification with the pinned contracts could alter their bytes.
	$(CARGO) build -p directory-contract --target $(WASM_TARGET) --release
	$(MAKE) check-imports W=$(WASM_DIR)/feed_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/inbox_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/avatar_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/directory_contract.wasm
	cp $(WASM_DIR)/feed_contract.wasm $(WASM_DIR)/inbox_contract.wasm $(WASM_DIR)/avatar_contract.wasm $(WASM_DIR)/directory_contract.wasm ui/contracts/
	$(MAKE) check-addresses

delegate:
	$(CARGO) build -p freebird-delegate --target $(WASM_TARGET) --release
	$(MAKE) check-imports W=$(WASM_DIR)/freebird_delegate.wasm
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

# Fail if a wasm imports anything outside the freenet host namespaces —
# a wasm-bindgen placeholder import means the getrandom poison is back
# (freenet/river#241) and the module will not instantiate under wasmtime.
check-imports:
	@bad=$$($(WASM_TOOLS) print $(W) | grep '(import' | grep -v '"freenet_' || true); \
	if [ -n "$$bad" ]; then echo "FORBIDDEN IMPORTS in $(W):"; echo "$$bad"; exit 1; fi
	@echo "$(W): imports clean"

# Contracts/delegate must be current first: the UI embeds their wasm
# (include_bytes) and derives contract addresses from those exact bytes.
ui: contracts delegate
	cd ui && $(DX) build --release

test:
	$(CARGO) test --workspace

publish:
	scripts/publish-ui.sh

clean:
	$(CARGO) clean
