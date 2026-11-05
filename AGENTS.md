# Repository guidance

`CLAUDE.md` points here. Read this before changing code.

## Layout

- `crates/ownership-token`: token claims, the verifier, the JWKS cache, and the `tower`/`axum` integration. A published library: keep its public API small and documented.
- `crates/ownership-gateway`: the issuing service and its `jwks` subcommand.
- `crates/ownership-proxy`: the verifying sidecar.

Integration tests live in each crate's `tests/` directory. Shared test helpers belong in a `tests/support` module of the crate that uses them, or behind a `test-util` feature when another crate needs them.

## Commands

Run everything inside the dev shell, which pins the Rust toolchain and the `nargo` version that `world-id-proof` needs to compile its bundled circuit: `nix develop --command <cmd>`.

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings
cargo test --locked --workspace --all-features
```

Integration tests start Redis through testcontainers and need Docker. Run all three commands before every commit.

## Testing

Prefer integration and end-to-end tests that drive the public HTTP API or the public library API. Use a real Redis, real ownership proofs and a real HTTP server, and fake only what the system talks to over the network: the World ID root endpoint and KMS. Add unit tests only for logic an integration test cannot reach, such as parsers and invariant-bearing types. Test rejected input as well as accepted input.

Keep tests deterministic: control time and randomness through explicit inputs and never sleep to wait for an event.

## Code style

- Match the surrounding code. Before adding a helper, check whether one exists.
- Names carry the domain concept and units (`challenge_ttl`, `expires_at`, `Duration` rather than a bare integer). Use one term per concept.
- Parse, don't validate: turn untrusted input (requests, config, env, JWKS documents, upstream responses) into types that hold their invariants, and reject invalid input at the boundary.
- Make illegal states unrepresentable with enums and private fields.
- Failures are part of the contract. Do not swallow errors or return success after partial failure. Add context without leaking tokens, proofs, subjects or keys. Retries are bounded and only for idempotent operations.
- Keep I/O at the edges: decisions in pure functions, effects in a thin shell. Pass clocks and randomness in explicitly where it keeps logic testable.
- Comments only for tricky invariants or warnings, describing the current code. Doc comments describe the contract (behaviour, errors, panics), in the style of the Rust standard library.
- Files read top to bottom: types before the code that uses them.
- No speculative abstractions, feature flags or configuration for imagined needs.

## Observability

Emit metrics for high-frequency events and logs only for warnings and errors. Never log or tag metrics with tokens, proofs, subjects, nonces, Merkle roots or keys. Metric tags must have bounded cardinality.

## Pull requests

Each PR does one thing and stays under about 1,000 changed lines, excluding `Cargo.lock`. PR titles follow Conventional Commits; the squash commit takes the PR title.
