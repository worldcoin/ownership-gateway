# syntax=docker/dockerfile:1

FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS builder
USER root
WORKDIR /app

COPY . .
RUN rustup show \
 && rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --locked \
      --target x86_64-unknown-linux-musl \
      --package ownership-proxy \
 && mv target/x86_64-unknown-linux-musl/release/ownership-proxy /app/ownership-proxy

FROM scratch AS runtime

# The JWKS is fetched over TLS.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/ownership-proxy /usr/local/bin/ownership-proxy

USER 65532

# Proxy, then admin (health and readiness).
EXPOSE 8080 8081

ENTRYPOINT ["/usr/local/bin/ownership-proxy"]
