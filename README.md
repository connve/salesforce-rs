# salesforce-rs

[![Test Suite](https://github.com/connve/salesforce-rs/actions/workflows/test.yml/badge.svg)](https://github.com/connve/salesforce-rs/actions/workflows/test.yml)
[![Security Audit](https://github.com/connve/salesforce-rs/actions/workflows/security.yml/badge.svg)](https://github.com/connve/salesforce-rs/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/connve/salesforce-rs)](https://github.com/connve/salesforce-rs/releases)

Unofficial Rust SDK family for the Salesforce platform. Each Salesforce product cloud has its own crate; install only the ones you need.

## Crates

| Crate | Product cloud |
|-------|---------------|
| [`salesforce_core`](https://crates.io/crates/salesforce_core) [![Crates.io](https://img.shields.io/crates/v/salesforce_core.svg)](https://crates.io/crates/salesforce_core) [![Docs.rs](https://docs.rs/salesforce_core/badge.svg)](https://docs.rs/salesforce_core) | Salesforce Core (Sales, Service, Platform) — REST, Bulk 2.0, Pub/Sub, Tooling |

For each crate's documentation, API coverage, and quick-start examples, see its dedicated README:

- [`salesforce-core/README.md`](salesforce-core/README.md) — Core APIs (REST, Bulk 2.0, Pub/Sub, Tooling)

## Project layout

```
salesforce-rs/
├── salesforce-core/           # User-facing crate for Core APIs
├── generated/
│   └── salesforce-core/       # Auto-generated API clients
│       ├── restapi/           # OpenAPI → progenitor
│       ├── composite/
│       ├── bulkapi/
│       ├── toolingapi/
│       └── pubsubapi/         # Protobuf → tonic
└── examples/                  # Per-product, per-API runnable examples
    └── salesforce-core/
```

When a new product cloud (Marketing Cloud, Data Cloud, etc.) is added, it gets its own user-facing crate at the workspace root and its own generated subtree under `generated/`.

## Development

### Running Tests

```bash
# Run all tests (unit + doc tests)
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture

# Run specific test
cargo test test_name
```

### Running Examples

All examples load credentials from a JSON file pointed to by `SFDC_CREDENTIALS`:

```bash
cat > credentials.json <<'EOF'
{
  "client_id": "your_client_id",
  "client_secret": "your_client_secret",
  "instance_url": "https://your-instance.my.salesforce.com",
  "tenant_id": "your_tenant_id"
}
EOF

export SFDC_CREDENTIALS=$PWD/credentials.json

cargo run --example restapi
```

### Running Integration Tests

Integration tests use the same `SFDC_CREDENTIALS` env var. Without it, they skip silently:

```bash
SFDC_CREDENTIALS=$PWD/credentials.json cargo test --test auth --test restapi --test composite --test bulkapi
```

### Releasing

Bump the version across the workspace and all path-dep declarations in one command:

```bash
cargo install cargo-workspaces  # one-time
cargo workspaces version --no-git-commit --yes patch  # or: minor, major
```

Commit the resulting `Cargo.toml` changes and merge to `main`. The release workflow detects the version bump, tags the commit, and publishes to crates.io.

### Code Quality Standards

- **No panics in production**: All production code uses `Result` types with `?` operator
- **Error handling**: Custom error types use `thiserror` with proper source chain preservation
- **Documentation**: All public APIs have comprehensive documentation with examples
- **Testing**: Unit tests, doc tests, and opt-in integration tests against a real Salesforce org
- **Dependency management**: All dependencies use workspace-level version management

## License

MPL-2.0

---

This is an unofficial SDK and is not affiliated with or endorsed by Salesforce.
