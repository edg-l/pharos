# syntax=docker/dockerfile:1.7
#
# Pharos multi-stage Dockerfile.
#
# Layout:
#   chef    -> shared base; installs cargo-chef.
#   planner -> derives a dependency recipe from the workspace.
#   builder -> cooks the recipe (deps only), then builds the workspace.
#   runtime -> slim debian carrying only the two binaries.
#
# Build:
#   DOCKER_BUILDKIT=1 docker build -t pharos:dev .
#
# Run:
#   docker run --rm -it -v $PWD/data:/var/lib/pharos \
#       -v $PWD/genesis.ssz:/genesis.ssz:ro \
#       -p 9000:9000/tcp -p 9000:9000/udp -p 9001:9001/udp \
#       pharos:dev --genesis-state-path /genesis.ssz
#

ARG RUST_VERSION=1.85
ARG DEBIAN_VERSION=bookworm

# --- chef ---------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS chef
ENV CARGO_TERM_COLOR=always \
    CARGO_NET_RETRY=10 \
    RUST_BACKTRACE=1 \
    CARGO_INCREMENTAL=0
RUN cargo install cargo-chef --locked --version 0.1.71
WORKDIR /pharos

# --- planner: emit recipe.json ------------------------------------------
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

# --- builder: cook deps, then compile -----------------------------------
FROM chef AS builder

# Native build deps for librocksdb-sys (clang + cmake) and blst.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        clang \
        libclang-dev \
        cmake \
        pkg-config \
        build-essential \
        git

# Cook dependencies in a separate layer; this caches as long as Cargo.lock
# and the workspace member list do not change.
COPY --from=planner /pharos/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/pharos/target \
    cargo chef cook --release --recipe-path recipe.json

# Build the actual workspace. Sources change frequently; deps do not.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY scripts ./scripts
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/pharos/target \
    cargo build --release --bin pharos --bin pharos-vc && \
    cp target/release/pharos    /usr/local/bin/pharos && \
    cp target/release/pharos-vc /usr/local/bin/pharos-vc

# --- runtime: minimal image with just the binaries ----------------------
FROM debian:${DEBIAN_VERSION}-slim AS runtime

# rocksdb pulls in bundled snappy/zstd/lz4 statically; we still need
# ca-certificates for TLS roots (rustls reads /etc/ssl/certs) and
# libstdc++6 for the bundled C++ runtime.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
        tini && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1000 pharos && \
    useradd  --system --uid 1000 --gid pharos --create-home --home-dir /var/lib/pharos pharos
USER pharos
WORKDIR /var/lib/pharos
VOLUME /var/lib/pharos

COPY --from=builder /usr/local/bin/pharos    /usr/local/bin/pharos
COPY --from=builder /usr/local/bin/pharos-vc /usr/local/bin/pharos-vc

# libp2p TCP / discv5 UDP / optional QUIC UDP.
EXPOSE 9000/tcp
EXPOSE 9000/udp
EXPOSE 9001/udp

LABEL org.opencontainers.image.title="Pharos" \
      org.opencontainers.image.description="From-scratch Rust Ethereum consensus client" \
      org.opencontainers.image.source="https://github.com/edg-l/pharos" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT" \
      org.opencontainers.image.vendor="Pharos"

# tini reaps zombies + forwards SIGTERM cleanly (important for Kurtosis
# enclave shutdown and CI runners).
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/pharos"]
CMD ["--help"]
