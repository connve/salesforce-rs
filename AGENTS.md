# AGENTS.md

Guidance for working on this repo, and on sibling SDKs that follow the same recipe.

## Repository shape

This is a Rust workspace that publishes an unofficial SDK for a third-party platform. The pattern used here is reusable for any SDK that wraps machine-readable API specs.

```
<sdk>/
├── <wrapper>/                  # User-facing crate: ergonomic wrappers, auth, retries
│   └── src/
│       ├── <api1>/             # Hand-written wrapper around generated/<api1>
│       ├── <api2>/
│       └── ...
├── generated/
│   └── <wrapper>/              # Auto-generated clients (one crate per spec)
│       ├── <api1>/             # OpenAPI  → progenitor
│       ├── <api2>/             # OpenAPI  → progenitor
│       └── <api3>/             # Protobuf → tonic
└── examples/
    └── <wrapper>/              # Runnable examples, one per API
```

**Split rationale:** generated code is regenerated frequently and breaks on every spec bump. Keeping it in its own crate means consumers depend on the wrapper, not the generator output. The wrapper crate re-exports types and provides ergonomic auth, retries, and cross-API helpers.

## Generic SDK recipe

Follow this recipe when starting a new SDK in the same family.

### 1. Generate, don't write, the API surface
- **OpenAPI specs → [`progenitor`](https://crates.io/crates/progenitor)** for REST APIs.
- **Protobuf → [`tonic`](https://crates.io/crates/tonic)** for gRPC.
- **No off-the-shelf generator?** Write custom codegen in a `build.rs` or a separate generator binary, not in the published crate.
- Each generated client lives in its own crate under `generated/`. Never edit generated files; fix the spec or the codegen step.

### 2. Normalize the spec before generation
Generators amplify spec quirks. Pre-process the spec so generated method names are idiomatic.
- Apply single-capital prefixes for acronyms in `operationId` (e.g. `listUrls`, not `listURLs`) so snake_case conversion produces `list_urls` rather than `list_u_r_ls`.
- Strip vendor extensions that confuse the generator.
- Keep the patcher script in the repo so regeneration is reproducible.

### 3. Wrapper crate provides the ergonomics
The user-facing crate owns:
- **Auth**: a single `Client` that handles token acquisition, refresh, and per-flow credential validation.
- **Per-API modules**: thin wrappers that hold a reference to the generated client plus shared config (base URL, API version).
- **Retry policy**: see §6.
- **Re-exports**: surface the generated types consumers actually need, hide internal plumbing.

### 4. Version & API-version constants
- One workspace `version` in the root `Cargo.toml`, propagated to all member crates.
- Use `cargo-workspaces` for releases: `cargo workspaces version --no-git-commit --yes patch`.
- Expose a `DEFAULT_API_VERSION: &str` constant from the wrapper crate's `lib.rs`. Never hardcode version strings at call sites.

### 5. Credentials via JSON file, not env vars
Tests and examples load credentials from a JSON file pointed to by a single env var, not from individual `*_USERNAME` / `*_SECRET` env vars. This avoids leaking secrets into shell history and keeps test setup to one line. Integration tests must skip silently when the env var is unset.

### 6. Retry policy: `is_retryable()` on every public Error
Every public `Error` enum exposes an `is_retryable(&self) -> bool` method so consumers can drive their own retry loops without pattern-matching internal variants. Transport errors and 5xx responses are retryable; auth failures and 4xx are not. Document the policy per variant.

The wrapper does not implement its own retry loop — that's the caller's job. The SDK's contract is "tell the caller whether this is worth retrying."

### 7. Workspace-level dependency management
- All dependency versions declared once in the root `[workspace.dependencies]`.
- Member crates use `dep = { workspace = true, features = [...] }`.
- Never declare versions directly in individual crates.

## Code quality standards

### Error handling
- **Never `unwrap()`, `expect()`, or `panic!()`** in production code. `expect()` in tests is fine.
- Use specific error variants per failure mode, not a single `Generic(String)` variant.
- Mark all public error enums `#[non_exhaustive]` so adding variants isn't a breaking change.
- Prefer `#[source]` over `#[from]` for granular control over the error chain. `#[from]` makes the conversion implicit, which is convenient but hides intent.
- Convert with `.map_err(|source| Error::Variant { source })`. Use `?` for propagation.
- Implement `is_retryable()` on every public Error enum (see recipe §6).

**Good:**
```rust
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Client secret is required for authentication")]
    MissingClientSecret,

    #[error("HTTP request failed")]
    Http {
        #[source]
        source: reqwest::Error,
    },
}
```

**Bad:**
```rust
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid credentials for {flow}: {message}")]
    InvalidCredentials { flow: String, message: String },
}
```

### Testing
**Test behavior, not implementation.**

- **Don't test** derive macros (`Clone`, `Debug`, `PartialEq`, `Serialize`), string formatting (`format!("{:?}")`), constants, trivial getters, or error message strings.
- **Do test** validation logic, state transitions, error conditions (via `matches!`), edge cases, integration points.
- Remove tests that just construct a value and assert nothing meaningful.

```rust
// Good
assert!(matches!(result, Err(Error::MissingClientSecret)));

// Bad
assert_eq!(error.to_string(), "Client secret is required for authentication");
```

### Module structure (Rust 2018+)
Use `module.rs` + `module/submodule.rs`. Never `module/mod.rs`.

```
src/
  lib.rs
  <api>.rs
  <api>/
    client.rs
    query.rs
```

### Standard libraries — don't reimplement
- **Time/date:** `chrono`. Never compute timestamps or timezones manually.
- **Errors:** `thiserror` for libraries, `anyhow` only in binaries/examples.
- **HTTP:** `reqwest` with `rustls`.
- **Serde:** `serde` + `serde_json`. Use `#[serde(default)]` for optional fields.

### Comments & documentation
- Default to writing no comments. Add one only when the *why* is non-obvious (hidden constraint, workaround, surprising invariant).
- Don't explain *what* the code does — names should do that.
- All public APIs get rustdoc. Examples in rustdoc use `# #[tokio::main]` for async, mark as `no_run` if they require credentials.
- Reference `<crate>::DEFAULT_API_VERSION` in examples; never hardcode.
- Comments must be complete sentences with proper punctuation. No commented-out code.

### Instrumentation
Public async methods get `#[cfg_attr(feature = "trace", tracing::instrument(skip_all))]`. Tracing stays behind a feature flag so consumers don't pay for it by default.

### Before considering any change complete
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

### Code style
- No emojis in code, comments, or commit messages unless explicitly requested.
- Let `rustfmt` handle formatting. Don't manually align.

## Git & releases

- Commits: conventional-commit style (`feat:`, `fix:`, `chore:`). Be specific about *why*, not just *what*.
- Never commit unless explicitly asked.
- Release flow: bump version via `cargo workspaces version`, merge to `main`, the release workflow tags and publishes to crates.io.

## What lives where

- **`AGENTS.md`** (this file): public, recipe-level guidance. Reusable across SDKs.
- **`README.md`**: user-facing — what the crates do, how to install and use them.
- **`CHANGELOG.md`**: per-release notes.
