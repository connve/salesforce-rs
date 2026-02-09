# Salesforce Rust SDK

[![Test Suite](https://github.com/connve-labs/salesforce-rs/actions/workflows/test.yml/badge.svg)](https://github.com/connve-labs/salesforce-rs/actions/workflows/test.yml)
[![Security Audit](https://github.com/connve-labs/salesforce-rs/actions/workflows/security.yml/badge.svg)](https://github.com/connve-labs/salesforce-rs/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/connve-labs/salesforce-rs)](https://github.com/connve-labs/salesforce-rs/releases)

Unofficial Rust SDK for the Salesforce API with support for OAuth2 authentication, Pub/Sub API, and Bulk API 2.0.

## Installation

This package is not yet published to crates.io. Install directly from GitHub:

```toml
[dependencies]
salesforce_core = { git = "https://github.com/connve-labs/salesforce-rs" }
```

## Examples

See [examples](examples/) directory for complete working code:
- [Pub/Sub API](examples/salesforce-core/pubsub.rs)
- [Bulk API 2.0](examples/salesforce-core/bulkapi.rs)

## Project Structure

```
salesforce-rs/
├── salesforce-core/           # Core SDK
│   └── src/
│       ├── client.rs          # OAuth2 authentication
│       ├── pubsub/            # Pub/Sub API client
│       └── bulkapi/           # Bulk API 2.0 client
├── generated/                 # Generated API code
│   ├── salesforce-core/v1/    # Bulk API 2.0 (OpenAPI)
│   └── salesforce-pubsub/v1/  # Pub/Sub API (gRPC)
└── examples/                  # Working examples
    └── salesforce-core/
```

## API Coverage

### Authentication

| Feature | Status |
|---------|--------|
| OAuth2 Client Credentials Flow | ✓ |
| OAuth2 Username-Password Flow | ✓ |
| Automatic Token Refresh | ✓ |
| Session Reconnection | ✓ |

### Pub/Sub API (gRPC)

| Operation | Status |
|-----------|--------|
| Get Topic | ✓ |
| Get Schema | ✓ |
| Subscribe | ✓ |
| Publish | ✓ |
| Publish Stream | ✓ |
| Get Topic by Schema ID | ✓ |

### Bulk API 2.0 - Query Operations

| Operation | Status |
|-----------|--------|
| Create Query Job | ✓ |
| Get Query Job Info | ✓ |
| Get Query Results | ✓ |
| Get Query Result Pages | ✓ |
| Get All Query Jobs | ✓ |
| Abort Query Job | ✓ |
| Delete Query Job | ✓ |

### Bulk API 2.0 - Ingest Operations

| Operation | Status |
|-----------|--------|
| Create Ingest Job | ✓ |
| Get Ingest Job Info | ✓ |
| Upload Job Data | ✓ |
| Mark Upload Complete | ✓ |
| Get Successful Results | ✓ |
| Get Failed Results | ✓ |
| Get Unprocessed Results | ✓ |
| Get All Ingest Jobs | ✓ |
| Abort Ingest Job | ✓ |
| Delete Ingest Job | ✓ |

## License

MPL-2.0

---

This is an unofficial SDK and is not affiliated with or endorsed by Salesforce.
