# syntax=docker/dockerfile:1

FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS builder
USER root
WORKDIR /app

# Keep these in sync with .github/workflows/ci.yml and nix/nargo.nix.
ENV NARGO_VERSION=1.0.0-beta.26 \
    NARGO_SHA256=64048040befd55a987158b11137d8f38f9688f696db4d84910dd1bcf0442fb80
RUN curl -fsSL -o /tmp/nargo.tgz "https://github.com/noir-lang/noir/releases/download/v${NARGO_VERSION}/nargo-x86_64-unknown-linux-gnu.tar.gz" \
 && echo "${NARGO_SHA256}  /tmp/nargo.tgz" | sha256sum --check \
 && tar -xzf /tmp/nargo.tgz -C /usr/local/bin \
 && rm /tmp/nargo.tgz

COPY . .
RUN rustup show \
 && rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --locked \
      --target x86_64-unknown-linux-musl \
      --package ownership-gateway \
 && mv target/x86_64-unknown-linux-musl/release/ownership-gateway /app/ownership-gateway

FROM scratch AS runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/ownership-gateway /usr/local/bin/ownership-gateway
USER 65532
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/ownership-gateway"]
