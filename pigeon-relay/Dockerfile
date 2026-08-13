# Build the relay, then ship just the binary on distroless (glibc) — small,
# multi-arch (amd64/arm64), and runs as a non-root user with no shell.
FROM rust:1.96.0-slim-trixie AS build
WORKDIR /src

# A blind mailbox does not need to be large or fast; optimize the standalone
# Docker build for size. These replace Cargo.toml profile settings so the relay
# can also live cleanly inside the repository workspace.
ENV CARGO_PROFILE_RELEASE_STRIP=true \
    CARGO_PROFILE_RELEASE_LTO=true \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=z \
    CARGO_PROFILE_RELEASE_PANIC=abort

COPY Cargo.toml Cargo.lock ./

RUN --mount=type=bind,source=pigeon-core,target=/src/pigeon-core,readonly \
    --mount=type=bind,source=pigeon-ffi,target=/src/pigeon-ffi,readonly \
    --mount=type=bind,source=pigeon-mesh,target=/src/pigeon-mesh,readonly \
    --mount=type=bind,source=pigeon-relay,target=/src/pigeon-relay,readonly \
    cargo build --locked --release -p pigeon-relay

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/pigeon-relay /usr/local/bin/pigeon-relay
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/pigeon-relay"]
