# Contributing to salesforce-rs

This document covers the conventions we follow across the Rust workspace and
the recipe that keeps this SDK consistent with sibling SDKs built the same
way. Read it before your first PR; skim it again whenever you're adding a new
API module or touching error handling.

Sections end with **Reference implementations** pointing at the files that
already do the thing being described — start there rather than from the prose.

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

**Reference implementations:**
- Proxy to the generated client's classification: `salesforce-core/src/restapi/sobject.rs`
- gRPC status-code classification: `salesforce-core/src/pubsubapi/client.rs`
- Transport-level classification: `salesforce-core/src/http.rs`
- SOAP faults, where a `sf:`-prefixed `<faultcode>` is permanent regardless of
  HTTP status: `salesforce-core/src/soapapi/merge.rs`
- Builder/config errors, which always report `false`:
  `salesforce-core/src/restapi/client.rs`

### 7. Request builders, dispatched with `.send()`
Public operations return a dedicated builder struct rather than a future. The
builder carries optional per-call configuration and is dispatched with
`.send().await`. This is what lets a caller set arbitrary Salesforce request
headers without every method growing an `Option<HeaderMap>` parameter.

Each builder:
- Is named after the operation (`Create`, `Get`, `GetDeleted`), borrows the
  client (`<'a>`), and holds a `HeaderBag`.
- Carries `#[must_use = "request builders do nothing until `.send().await` is called"]`,
  so forgetting `.send()` is a warning rather than a silent no-op.
- Exposes `.header(name, value)` and `.headers(map)`, plus one method per
  optional query parameter.
- Puts `#[cfg_attr(feature = "trace", tracing::instrument(skip_all))]` on
  `.send()`, not on the constructor.

Required arguments go in the constructor; everything optional goes on the
builder:

```rust
rest.get("Account", id).fields("Id,Name").send().await?;
rest.delete_records(ids).all_or_none(false).send().await?;
```

**Reference implementations:**
- The full set of SObject builders, including the header plumbing
  (`HeaderBag`, `http_client_with`): `salesforce-core/src/restapi/sobject.rs`
- Builders over collection endpoints: `salesforce-core/src/restapi/composite.rs`

`search()` and `invoke_flow*()` predate this pattern and still take their
arguments directly; migrating them is open work.

### 8. Workspace-level dependency management
- All dependency versions declared once in the root `[workspace.dependencies]`.
- Member crates use `dep = { workspace = true, features = [...] }`.
- Never declare versions directly in individual crates.
- Generated crates are pinned by exact version in `[workspace.dependencies]`
  alongside their `path`. A release bump has to update both, or the workspace
  stops resolving.

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

Two tiers, picked by what the code under test touches:

- **Unit tests**: `#[cfg(test)] mod tests` inline in the file. Default choice
  for validation logic, error classification, and anything that doesn't need
  a live org.
- **Integration tests**: `salesforce-core/tests/<api>.rs`, one file per API.
  These hit a real Salesforce org, so they open with `skip_if_no_credentials!()`
  and exit quietly when `SFDC_CREDENTIALS` is unset — `cargo test` has to pass
  on a machine with no org configured.

Credentials come from a JSON file pointed at by `SFDC_CREDENTIALS`, loaded by
the shared helpers in `salesforce-core/tests/common.rs`. Never read individual
`*_USERNAME` / `*_SECRET` env vars.

Where a Salesforce-side operation is asynchronous (deleted-record replication,
bulk job completion), assert that the call succeeds rather than that the data
has already propagated — the latter is flaky by construction. Say so in a
comment, so the weak assertion doesn't read as an oversight.

**Reference implementations:**
- Credential loading and the skip macro: `salesforce-core/tests/common.rs`
- REST integration tests, including the asynchronous-propagation case:
  `salesforce-core/tests/restapi.rs`
- Runnable per-API examples: `examples/salesforce-core/`

### Module structure (Rust 2018+)
New modules use `module.rs` + `module/submodule.rs`, not `module/mod.rs`.

```
src/
  lib.rs
  <api>.rs
  <api>/
    client.rs
    query.rs
```

The existing API modules (`restapi`, `bulkapi`, `pubsubapi`, `soapapi`,
`toolingapi`) predate this rule and still use `mod.rs`. Leave them alone —
renaming them churns `git blame` across the whole crate for no functional
gain. Apply the rule to modules you add.

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

### Linting
Lint levels live in `[workspace.lints.clippy]` in the root `Cargo.toml`, and
crates opt in with `[lints] workspace = true`. `clippy::all` is denied, so
`cargo clippy --workspace --all-targets --all-features -- -D warnings` passing
is the bar for any change.

Write suppressions as `#[expect(lint, reason = "...")]` on the smallest item
that needs them — `allow_attributes` and `allow_attributes_without_reason` are
denied, so clippy will point you there. The reason `#[expect]` is the required
form: clippy reports it as unfulfilled once the underlying lint stops firing,
so a suppression that has outlived its cause shows up as an error instead of
sitting there indefinitely.

Fix `result_large_err` by boxing the oversized source
(`source: Box<GeneratedError>`), the way the REST error enums do. Boxing a
`#[source]` field keeps the public shape intact — the variant exposes the
`#[source]` accessor, not the pointer behind it.

Generated crates under `generated/` stay out of this: they don't opt into
workspace lints, because their suppressions are emitted by the generator and
would come back on the next regeneration.

### Before considering any change complete
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace`
- For a user-visible change: bump the version and add a `CHANGELOG.md` entry
  (see **Git & releases**).

### Code style
- No emojis in code, comments, or commit messages unless explicitly requested.
- Let `rustfmt` handle formatting. Don't manually align.

## Git & releases

- Commits: conventional-commit style (`feat:`, `fix:`, `chore:`). Be specific about *why*, not just *what*.
- Commit when you're explicitly asked to.
- Release flow: bump version via `cargo workspaces version`, merge to `main`, the release workflow tags and publishes to crates.io.

### Versioning and the changelog

Every PR that changes the public API carries its own version bump and
changelog entry — both belong in the PR, not in a later release-time pass.

- New public API (a method, a builder, a re-exported type) is a **minor** bump.
  Bug fixes with no signature change are a **patch**. A changed or removed
  signature is a breaking change: bump minor while pre-1.0 and mark the entry
  **Breaking:** with a before/after migration line.
- Bump with `cargo workspaces version --no-git-commit --yes <minor|patch>`.
  It only rewrites crates that changed since the last tag, so afterwards
  confirm that `[workspace.package] version` and all four pinned
  `salesforce_core_*` versions in `[workspace.dependencies]` agree — a partial
  bump leaves the workspace unable to resolve.
- Add the entry under a new `## [x.y.z] - YYYY-MM-DD` heading in
  `CHANGELOG.md`, grouped **Added** / **Changed** / **Fixed**. Describe what a
  consumer can now do; for anything breaking, show the old and new call side
  by side.

## What lives where

- **`CONTRIBUTORS.md`** (this file): contributor-facing conventions and
  recipe-level guidance. The recipe sections are reusable across sibling SDKs;
  the reference implementations are specific to this repo.
- **`README.md`**: user-facing — what the crates do, how to install and use them.
- **`CHANGELOG.md`**: per-release notes.
