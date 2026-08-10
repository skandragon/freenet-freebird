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

.PHONY: all contracts delegate ui test check-imports publish clean

all: test contracts delegate ui

contracts:
	$(CARGO) build -p feed-contract -p inbox-contract --target $(WASM_TARGET) --release
	$(MAKE) check-imports W=$(WASM_DIR)/feed_contract.wasm
	$(MAKE) check-imports W=$(WASM_DIR)/inbox_contract.wasm
	cp $(WASM_DIR)/feed_contract.wasm $(WASM_DIR)/inbox_contract.wasm ui/contracts/

delegate:
	$(CARGO) build -p freebird-delegate --target $(WASM_TARGET) --release
	$(MAKE) check-imports W=$(WASM_DIR)/freebird_delegate.wasm
	cp $(WASM_DIR)/freebird_delegate.wasm ui/contracts/

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
