# Build the relay, then ship just the binary on distroless (glibc) — small,
# multi-arch (amd64/arm64), and runs as a non-root user with no shell.
FROM rust:1.96.0-slim-trixie AS build
WORKDIR /src

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
