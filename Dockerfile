# syntax=docker/dockerfile:1.6
#
# Multi-arch build for aperion-shield.
#
# Built and published to ghcr.io/aperionai/shield:<version> by
# .github/workflows/shield-release.yml. The image is intentionally
# minimal — just the static binary on top of distroless so it can be
# audited in seconds and has no shell / package manager attack surface.

# ─── Build stage ───────────────────────────────────────────────────────
FROM rust:1.81-slim-bookworm AS build

WORKDIR /src

# Cache the dependency layer first
COPY Cargo.toml ./
RUN mkdir src && echo "fn main(){}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Bring in the real source. The standalone crate also needs the
# bundled config from the parent repo at build time.
COPY src ./src
COPY ../../config/shieldset.yaml /src/../../config/shieldset.yaml

RUN cargo build --release && \
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
