# ownership-gateway

Exchanges a World ID ownership proof ([WIP-103](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-103.md)) for a short-lived, audience-scoped JWT, and verifies that JWT in front of backend services.

A client asks the gateway for a challenge, proves with its authenticator that it controls a registered World ID account, and exchanges the proof for a token. Backends then check the token locally against the gateway's public keys, without receiving the proof on every request.

| Crate | What it is |
| --- | --- |
| `ownership-gateway` | Token issuer: challenges, proof verification, KMS signing, and the JWKS endpoint (`ownership-gateway jwks`). |
| `ownership-token` | Token claims and verification: a JWKS cache, a `tower` layer and an `axum` extractor. Published to crates.io. |
| `ownership-proxy` | Sidecar that verifies tokens and forwards verified requests to a local service. |

An ownership proof shows control of an authenticator key of a registered account. It does not prove personhood or that one person holds one account.

## Development

Building the gateway needs `nargo` 1.0.0-beta.26; the Nix dev shell provides it and the pinned Rust toolchain (`nix develop`).

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings
cargo test --locked --workspace --all-features
```

Integration tests start Redis and LocalStack with testcontainers, so they need a running Docker daemon.

## Running the gateway

`ownership-gateway serve` issues challenges (`POST /v1/challenges`) and tokens (`POST /v1/tokens`) on `OWNERSHIP_GATEWAY_LISTEN` (`0.0.0.0:8080`) and serves `/health` and `/ready` on `OWNERSHIP_GATEWAY_ADMIN_LISTEN` (`0.0.0.0:8081`). `ownership-gateway serve --help` lists every setting. It requires:

| Variable | Value |
| --- | --- |
| `OWNERSHIP_GATEWAY_ISSUER` | The HTTPS issuer URL. Challenges point clients at `{issuer}/v1/tokens`. |
| `OWNERSHIP_GATEWAY_REDIS_URL` | A `rediss://` URL with the auth token; plaintext Redis is rejected. Neither `--help` nor a parse error prints it. |
| `OWNERSHIP_GATEWAY_AUDIENCE_POLICY_PATH` | The audience policy file. |
| `OWNERSHIP_GATEWAY_ROOT_SOURCE_URL` | The root service, `world-id-gateway`, which answers `is-valid-root`. It is not printed either. |
| `OWNERSHIP_GATEWAY_KMS_SIGNING_KEY_ID` | The P-256 KMS key that signs tokens. |
| `OWNERSHIP_GATEWAY_VERIFY_QUEUE_DEPTH` | How many verifications may wait for a worker. Each waiting request may hold a 1 MiB body and its decoded proof, so size it from pod memory. |

`OWNERSHIP_GATEWAY_TOKEN_ISSUANCE_ENABLED=false` makes both endpoints answer 503: the global kill switch. Disabling an audience in the policy stops new challenges and exchanges for that audience only.

The audience policy is a JSON array, for example:

```json
[{"aud":"service-a","enabled":true,"token_ttl_secs":600,"allowed_origins":["https://app.example"]}]
```

`ownership-gateway jwks` serves `/.well-known/jwks.json` with the keys listed in `OWNERSHIP_GATEWAY_KMS_PUBLISHED_KEY_IDS` (comma-separated), on the same listener and admin addresses. Its readiness depends only on having loaded those keys.

The gateway verifies WIP-103-001 (Issuer Authentication) proofs on main with `world-id-proof` 0.20.0 and its fixed credential-sub separator. The token `sub` is the credential `sub`. Consumers must compare `sub` with the account targeted by the operation, and clients must prove only as part of a user action.

### API errors

Errors have the shape `{"error":{"code":"...","message":"..."}}`. A token request claims its challenge before verifying, so each challenge gets one attempt: once claimed, every outcome other than a token spends it.

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `malformed_request` | The body is not the expected JSON. |
| 413 | `body_too_large` | The body exceeds 4 KiB for challenges or 1 MiB for tokens. |
| 403 | `audience_not_allowed` | The audience is unknown or disabled. |
| 403 | `origin_not_allowed` | The browser origin is not allowed for the audience. |
| 401 | `challenge_unusable` | The challenge is unknown, expired, spent or already attempted. Request a new challenge. |
| 401 | `proof_rejected` | The proof, or the root it was made against, was rejected. |
| 503 | `retry_later` | Nothing was spent: issuance is disabled, the challenge could not be stored, a challenge request ran past the request deadline, or verification capacity is full (with `Retry-After`). Retry the same request. |
| 503 | `request_new_challenge` | A dependency failed after the claim, or a token request ran past the request deadline, so the challenge may be spent. Request a new challenge, after `Retry-After` if it is set (KMS throttled signing, which is not retried). |

### Probes

`/health` makes no remote calls. On issuance pods the admin listener opens only after the verifier artifacts load, so a startup probe on `/health` covers loading. `/ready` then answers 503 until the signing key has loaded from KMS, and afterwards whenever Redis does not accept a write (a replica after a failover does not, and the gateway then replaces its Redis connection), three consecutive signing attempts have failed (`OWNERSHIP_GATEWAY_KMS_FAILURE_THRESHOLD`), or every root check has failed for 30 seconds (`OWNERSHIP_GATEWAY_ROOT_FAILURE_WINDOW_SECS`). An unready signer or root service is probed every 20 to 40 seconds, so readiness recovers without traffic. The probe has no hysteresis of its own; set the readiness probe's `failureThreshold` above one.

### Shutdown

On `SIGTERM` or `SIGINT` both subcommands answer 503 on `/ready`, stop accepting connections, and wait up to `OWNERSHIP_GATEWAY_SHUTDOWN_GRACE_SECS` (45) for requests in flight before exiting. Set the pod's `terminationGracePeriodSeconds` above that grace period plus any `preStop` delay. A short `preStop` sleep lets the endpoint removal reach the load balancer before the gateway stops accepting connections.

### Metrics

Both subcommands log, trace and send metrics as configured by the `TELEMETRY_*` variables of [`telemetry-batteries`](https://github.com/worldcoin/telemetry-batteries). On Kubernetes with the Datadog agent, set:

| Variable | Value |
| --- | --- |
| `TELEMETRY_PRESET` | `datadog`, with `TELEMETRY_SERVICE_NAME`, for JSON logs and traces to the agent. |
| `TELEMETRY_METRICS_BACKEND` | `statsd`. |
| `TELEMETRY_STATSD_HOST`, `TELEMETRY_STATSD_PORT` | The agent's DogStatsD address, usually the node IP (`fieldRef: status.hostIP`) and `8125`. `TELEMETRY_STATSD_PREFIX` is optional. |
| `DD_SERVICE`, `DD_ENV`, `DD_VERSION` | Datadog unified service tagging; the `common-app` chart sets them. |
| `DD_ENTITY_ID` | The pod UID, from the downward API: `valueFrom: {fieldRef: {fieldPath: metadata.uid}}`. |

With `TELEMETRY_METRICS_BACKEND=statsd`, the gateway installs the StatsD recorder itself instead of the `telemetry-batteries` one, so that every metric carries `service`, `env` and `version` from the `DD_*` variables and `dd.internal.entity_id` from `DD_ENTITY_ID`. The entity ID is Datadog's origin detection for UDP: the agent adds the pod's tags (`kube_namespace`, `pod_name`, `kube_deployment`, …) to each metric. Without it, metrics carry host tags only, and gauges from two pods on one node overwrite each other. An unset or empty variable adds no tag; a value with whitespace, `,` or `|` stops startup.

| Metric | Type | Tags | Meaning |
| --- | --- | --- | --- |
| `ownership_gateway.http.requests` | counter | `route`, `status_class` | Every public request, including 413s and deadline 503s. `route` is the matched route template, or `unmatched`. |
| `ownership_gateway.http.duration` | distribution | `route` | Seconds per public request. |
| `ownership_gateway.challenges.issued` | counter | `aud` | Challenges stored. |
| `ownership_gateway.tokens.issued` | counter | `aud` | Tokens signed and returned. |
| `ownership_gateway.tokens.rejected` | counter | `aud`, `reason` | Why an exchange was rejected: `unknown_challenge`, `attempt_taken`, `audience_disabled`, `origin_not_allowed`, `malformed_proof`, `invalid_proof`, `root_invalid` or `challenge_consumed`. The response says only `challenge_unusable`, `proof_rejected` or `origin_not_allowed`. Rejections before a challenge is found, including an origin that no audience allows, carry no `aud`. |
| `ownership_gateway.tokens.deadline_exhausted` | counter | `aud` | Exchanges stopped before the consume because too little of the request deadline was left; the challenge stays claimed. A steady rate means `OWNERSHIP_GATEWAY_REQUEST_DEADLINE_MS` is too tight or a dependency is slow. |
| `ownership_gateway.verify.shed` | counter | | Token requests shed because every verification place was taken (503 `retry_later`). |
| `ownership_gateway.verify.queue_wait` | histogram | | Seconds a verification waited for a worker. |
| `ownership_gateway.verify.duration` | histogram | | Seconds per verification, including the wait for a worker. |
| `ownership_gateway.dependency.duration` | histogram | `dep` | Seconds per attempt against `redis`, `root` or `kms`. |
| `ownership_gateway.dependency.errors` | counter | `dep`, `class` | Failed attempts; `class` is `timeout`, `connect`, `5xx`, `throttled` or `other`. |
| `ownership_gateway.ready` | gauge | `component` | 1 if `redis`, `root` or `kms` was ready at the last `/ready` probe, 0 if not. |
| `ownership_gateway.jwks.keys` | gauge | | Keys that `ownership-gateway jwks` publishes. |
| `ownership_gateway.jwks.served` | counter | | JWKS responses served. |

Only `http.duration` is sent as a distribution, which Datadog aggregates across pods; the other histograms are aggregated by the agent on each node.
