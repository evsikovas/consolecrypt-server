# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
#
# Uses the built-in BuildKit frontend (no `# syntax=` line, so building does
# not need to fetch a frontend image from a registry).
#
# ConsoleCrypt server image. Build from the REPOSITORY ROOT (the server
# depends on the shared crates in ./crates):
#
#   docker build -f server/Dockerfile -t consolecrypt-server .
#
# Runtime: distroless (glibc, no shell, no package manager), non-root.

ARG RUST_IMAGE=rust:1.98-slim-bookworm
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY rust-toolchain.toml ./
COPY crates ./crates
COPY server ./server
WORKDIR /src/server
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/server/target \
    cargo build --release --locked --bin consolecrypt-server \
    && cp target/release/consolecrypt-server /consolecrypt-server

FROM ${RUNTIME_IMAGE}
LABEL org.opencontainers.image.title="consolecrypt-server" \
      org.opencontainers.image.description="Self-hosted zero-knowledge sync server for ConsoleCrypt" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.authors="Alexander Evsikov <i@evsikov.net>" \
      org.opencontainers.image.vendor="Alexander Evsikov" \
      org.opencontainers.image.source="https://git.evsikov.net/publics/consolecrypt"
COPY --from=build /consolecrypt-server /usr/local/bin/consolecrypt-server
USER 65532:65532
ENV CC_LISTEN_ADDR=0.0.0.0:8080 \
    CC_METRICS_LISTEN=0.0.0.0:9090 \
    CC_LOG_FORMAT=json
EXPOSE 8080 9090
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/consolecrypt-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/consolecrypt-server"]
CMD ["serve"]
