# syntax=docker/dockerfile:1.6
#
# Multi-arch build for aperion-shield.
#
# Built and published to ghcr.io/aperionai/shield:<version> by
# .github/workflows/shield-release.yml. The image is intentionally
# minimal — just the static binary on top of distroless so it can be
# audited in seconds and has no shell / package manager attack surface.

# ─── Build stage ───────────────────────────────────────────────────────
# Pin to a Rust release that supports edition 2024 (≥ 1.85). Several of
# our transitive deps require it; rust:1.81 fails the dependency-cache
# layer with "edition2024 is unstable".
FROM rust:1.95-slim-bookworm AS build

WORKDIR /src

# Cache the dependency layer first. Both Cargo.toml AND Cargo.lock are
# copied so the stub-build resolves the exact same versions the real
# build will use; otherwise the cache is silently invalidated on every
# real build and we re-download the universe twice.
#
# v0.2.0+ has both a [lib] (src/lib.rs) AND a [bin] (src/main.rs)
# target, so the stub must satisfy both — `cargo build` fails fast if
# any target named in Cargo.toml is missing its entry point.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main(){}"      > src/main.rs && \
    echo "// stub for cache" > src/lib.rs && \
    cargo build --release --locked && \
    rm -rf src

# Bring in the real source and the vendored shieldset that
# `include_str!` in src/engine.rs embeds at compile time.
COPY src    ./src
COPY config ./config

# Touch the source files so cargo treats them as newer than the cached
# stub (otherwise the stub objects can be re-used and we'd ship them).
RUN find src -name '*.rs' -exec touch {} + && \
    cargo build --release --locked && \
    strip target/release/aperion-shield

# ─── Runtime stage ─────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="aperion-shield"
LABEL org.opencontainers.image.description="Local MCP guardrail for AI coding agents"
LABEL org.opencontainers.image.source="https://github.com/AperionAI/shield"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="Aperion"

COPY --from=build /src/target/release/aperion-shield /usr/local/bin/aperion-shield

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/aperion-shield"]
