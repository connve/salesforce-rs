# Salesforce Rust SDK

[![Test Suite](https://github.com/connve-labs/salesforce-rs/actions/workflows/test.yml/badge.svg)](https://github.com/connve-labs/salesforce-rs/actions/workflows/test.yml)
[![Security Audit](https://github.com/connve-labs/salesforce-rs/actions/workflows/security.yml/badge.svg)](https://github.com/connve-labs/salesforce-rs/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/connve-labs/salesforce-rs)](https://github.com/connve-labs/salesforce-rs/releases)

Unofficial Rust SDK for the Salesforce API with support for OAuth2 authentication, Pub/Sub API, Bulk API 2.0, SObject REST API, and Tooling API.

## Features

- **Full OAuth2 Support**: Client credentials flow, username-password flow, automatic token refresh
- **Pub/Sub API (gRPC)**: Subscribe to platform events and Change Data Capture with managed subscriptions
- **Bulk API 2.0**: High-performance query and ingest operations for large data sets
- **REST API**: Complete SObject CRUD operations with field-level control
- **Tooling API**: Create and manage Change Data Capture subscriptions
- **Type Safety**: Leverages Rust's type system with generated client code from OpenAPI specs
- **Error Handling**: Comprehensive error types with proper source chain preservation
- **Async/Await**: Built on Tokio for efficient concurrent operations
- **Zero Production Panics**: No unwrap/expect/panic in production code paths

## Installation

This package is not yet published to crates.io. Install directly from GitHub:

```toml
[dependencies]
salesforce_core = { git = "https://github.com/connve-labs/salesforce-rs" }
```

## Quick Start

### SObject CRUD Operations

```rust
use salesforce_core::client;
use salesforce_core::restapi;
use serde_json::json;
use std::path::PathBuf;

let auth_client = client::Builder::new()
    .credentials_path(PathBuf::from(std::env::var("SFDC_CREDENTIALS")?))
    .build()?
    .connect()
    .await?;

let rest_client = restapi::ClientBuilder::new(auth_client).build()?;

// Create a record
let data = json!({
    "Name": "Acme Corporation",
    "Industry": "Technology"
});
let response = rest_client.create("Account", data).await?;
let record_id = response.id;

// Read a record
let record = rest_client.get("Account", &record_id, None).await?;

// Update a record
let update_data = json!({ "Industry": "Manufacturing" });
rest_client.update("Account", &record_id, update_data).await?;

// Delete a record
rest_client.delete("Account", &record_id).await?;
```

### Managed Event Subscriptions

```rust
use salesforce_core::toolingapi::{self, ManagedEventSubscriptionMetadata, ReplayPreset, SubscriptionState};
use salesforce_core::pubsubapi::{Client as PubSubClient, ManagedFetchRequest};

// Step 1: Create managed subscription via Tooling API
let tooling_client = toolingapi::ClientBuilder::new(auth_client.clone()).build()?;

let subscription = toolingapi::CreateManagedEventSubscriptionRequest {
    full_name: "Managed_Sub_OpportunityChangeEvent".to_string(),
    metadata: ManagedEventSubscriptionMetadata {
        label: "Managed Sub OpportunityChangeEvent".to_string(),
        topic_name: "/data/OpportunityChangeEvent".to_string(),
        default_replay: ReplayPreset::Latest,
        state: SubscriptionState::Run,
        error_recovery_replay: ReplayPreset::Latest,
    },
};

let response = tooling_client.create_managed_event_subscription(subscription).await?;

// Step 2: Subscribe to events via Pub/Sub API
let channel = tonic::transport::Channel::from_static(salesforce_core::pubsubapi::ENDPOINT)
    .connect()
    .await?;

let mut pubsub_client = PubSubClient::new(channel, auth_client)?;

let request = ManagedFetchRequest {
    developer_name: "Managed_Sub_OpportunityChangeEvent".to_string(),
    num_requested: 100,
    ..Default::default()
};

let stream = pubsub_client.managed_subscribe(request).await?;
// Process events from stream...
```

## Examples

See [examples](examples/) directory for complete working code:
- [REST API](examples/salesforce-core/restapi.rs) - SObject CRUD operations (create, read, update, delete, describe)
- [Bulk API 2.0](examples/salesforce-core/bulkapi.rs) - Query and ingest operations for large data sets
- [Tooling API](examples/salesforce-core/toolingapi.rs) - Create managed event subscriptions for Change Data Capture
- [Pub/Sub API](examples/salesforce-core/pubsubapi.rs) - Subscribe to platform events and CDC events via gRPC

Run examples with:
```bash
cargo run --example restapi
cargo run --example bulkapi
cargo run --example toolingapi
cargo run --example pubsubapi
```

## Project Structure

```
salesforce-rs/
├── salesforce-core/           # Core SDK
│   └── src/
│       ├── client.rs          # OAuth2 authentication
│       ├── http.rs            # Shared HTTP client utilities
│       ├── pubsubapi/         # Pub/Sub API client
│       │   ├── mod.rs
│       │   └── client.rs
│       ├── bulkapi/           # Bulk API 2.0 client
│       │   ├── mod.rs
│       │   ├── client.rs
│       │   ├── query.rs       # Query operations
│       │   └── ingest.rs      # Ingest operations
│       ├── restapi/           # REST API
│       │   ├── mod.rs
│       │   ├── client.rs      # Shared REST API client
│       │   └── sobject.rs     # SObject CRUD operations
│       └── toolingapi/        # Tooling API (metadata operations)
│           ├── mod.rs
│           ├── client.rs
│           ├── types.rs       # Request/response types
│           └── error.rs       # Error handling
├── generated/                 # Generated API code (OpenAPI/gRPC)
│   └── salesforce-core/
│       ├── bulkapi/           # Bulk API 2.0 (OpenAPI generated)
│       ├── restapi/           # REST API (OpenAPI generated)
│       ├── toolingapi/        # Tooling API (OpenAPI generated)
│       └── pubsubapi/         # Pub/Sub API (gRPC/protobuf generated)
└── examples/                  # Working examples
    └── salesforce-core/
        ├── restapi.rs
        ├── bulkapi.rs
        ├── toolingapi.rs
        └── pubsubapi.rs
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
| Managed Subscribe | ✓ |
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

### SObject REST API

| Operation | Status |
|-----------|--------|
| Create Record | ✓ |
| Get Record | ✓ |
| Get Record by External ID | ✓ |
| Update Record | ✓ |
| Delete Record | ✓ |
| Get SObject Basic Info | ✓ |
| Describe SObject | ✓ |

### Composite REST API

| Operation | Status |
|-----------|--------|
| Create Records (batch) | ✓ |
| Update Records (batch) | ✓ |
| Delete Records (batch) | ✓ |
| Retrieve Records (batch) | ✓ |
| Upsert Records (batch) | ✓ |
| Create Record Tree | ✓ |

### Search

| Operation | Status |
|-----------|--------|
| SOSL Search | ✓ |

### Tooling API

| Operation | Status |
|-----------|--------|
| Create Managed Event Subscription | ✓ |
| Get Managed Event Subscription | - |
| Update Managed Event Subscription | - |
| Delete Managed Event Subscription | - |

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
