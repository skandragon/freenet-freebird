# Hermetic, reproducible builder for the non-frozen contract + delegate wasm.
# The image pins the exact toolchain so the same source yields byte-identical
# wasm on any host arch (arm64 laptop, amd64 CI) — contract/delegate addresses
# are content-derived, so identical bytes == identical addresses.
#
# NOTE: this image never builds the FROZEN cell-contract nor any *_v1 blob.
# See the wasm-repro / build-docker / repro-check targets in the Makefile.
FROM rust:1.95.0-bookworm

RUN rustup target add wasm32-unknown-unknown

# wasm-tools is only used by check-imports (it does not touch the wasm bytes).
# Pinned to what the repo builds with; prebuilt binary keeps image builds fast.
ARG WASM_TOOLS_VERSION=1.243.0
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=x86_64 ;; \
      arm64) arch=aarch64 ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/bytecodealliance/wasm-tools/releases/download/v${WASM_TOOLS_VERSION}/wasm-tools-${WASM_TOOLS_VERSION}-${arch}-linux.tar.gz"; \
    curl -fsSL "$url" -o /tmp/wasm-tools.tar.gz; \
    tar xzf /tmp/wasm-tools.tar.gz -C /tmp; \
    install -m0755 "/tmp/wasm-tools-${WASM_TOOLS_VERSION}-${arch}-linux/wasm-tools" /usr/local/bin/wasm-tools; \
    rm -rf /tmp/wasm-tools.tar.gz "/tmp/wasm-tools-${WASM_TOOLS_VERSION}-${arch}-linux"; \
    wasm-tools --version

# Fixed, arch-independent build paths. CARGO_HOME is world-writable so the
# container can run as the host uid (avoids root-owned files on the mount).
ENV CARGO_HOME=/cargo
RUN mkdir -p /cargo && chmod 0777 /cargo
WORKDIR /build
