# ownership-gateway

Exchanges a World ID ownership proof ([WIP-103](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-103.md)) for a short-lived, audience-scoped JWT, and verifies that JWT in front of backend services.

A client asks the gateway for a challenge, proves with its authenticator that it controls a registered World ID account, and exchanges the proof for a token. Backends then check the token locally against the gateway's public keys, without receiving the proof on every request.

| Crate | What it is |
| --- | --- |
| `ownership-gateway` | Token issuer: challenges, proof verification, KMS signing, and the JWKS endpoint (`ownership-gateway jwks`). |
| `ownership-token` | Token claims and verification: a JWKS cache, a `tower` layer and an `axum` extractor. Published to crates.io. |
| `ownership-proxy` | Sidecar that verifies tokens and forwards verified requests to a local service. |

An ownership proof shows control of an authenticator key of a registered account. It does not prove personhood or that one person holds one account.

## Proxy telemetry

The proxy sends DogStatsD metrics to `TELEMETRY_STATSD_HOST` (default `localhost`)
and `TELEMETRY_STATSD_PORT` (default `8125`). `TELEMETRY_STATSD_PREFIX` optionally
prefixes metric names. The proxy installs its own recorder; telemetry-batteries
initializes tracing only, regardless of `TELEMETRY_METRICS_BACKEND`.

Set `DD_SERVICE`, `DD_ENV`, and `DD_VERSION` for Datadog unified service tagging.
For a sidecar, `DD_SERVICE` identifies the consumer service. Set `DD_ENTITY_ID`
from the pod UID to enable Datadog UDP origin detection and pod tags:

```yaml
- name: DD_ENTITY_ID
  valueFrom:
    fieldRef:
      fieldPath: metadata.uid
```

Unset variables do not add tags.

## Development

Building the gateway needs `nargo` 1.0.0-beta.26; the Nix dev shell provides it and the pinned Rust toolchain (`nix develop`).

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings
cargo test --locked --workspace --all-features
```

Integration tests start Redis with testcontainers, so they need a running Docker daemon.

## Images and releases

The proxy image is published to `ghcr.io/worldcoin/ownership-proxy` for amd64.
Deploy by `sha-<7>` tag or image digest. A tag such as `ownership-proxy/v0.1.0`
publishes the versioned image and creates a draft GitHub release with its digest.
Stable version tags and pushes to `main` also update `latest`.

Release-plz prepares and publishes the `ownership-token` crate; `ownership-proxy`
is not published to crates.io. Crate publishing requires crates.io trusted publishing
configured for this repository and the release workflow.
