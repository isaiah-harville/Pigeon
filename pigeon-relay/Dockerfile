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

COPY Cargo.toml ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/pigeon-relay /usr/local/bin/pigeon-relay
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/pigeon-relay"]
