# Salesforce Rust SDK

[![Test Suite](https://github.com/connve-labs/salesforce-rs/actions/workflows/test.yml/badge.svg)](https://github.com/connve-labs/salesforce-rs/actions/workflows/test.yml)
[![Security Audit](https://github.com/connve-labs/salesforce-rs/actions/workflows/security.yml/badge.svg)](https://github.com/connve-labs/salesforce-rs/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/connve-labs/salesforce-rs)](https://github.com/connve-labs/salesforce-rs/releases)

Unofficial Rust SDK for the Salesforce API with support for OAuth2 authentication, Pub/Sub API, Bulk API 2.0, SObject REST API, and Tooling API.

## Installation

This package is not yet published to crates.io. Install directly from GitHub:

```toml
[dependencies]
salesforce_core = { git = "https://github.com/connve-labs/salesforce-rs" }
```

## Quick Start

### SObject CRUD Operations

```rust
use salesforce_core::client::{self, Credentials};
use salesforce_core::sobject;
use serde_json::json;

let auth_client = client::Builder::new()
    .credentials(Credentials { /* ... */ })
    .build()?
    .connect()
    .await?;

let sobject_client = sobject::ClientBuilder::new(auth_client).build();

// Create a record
let data = json!({
    "Name": "Acme Corporation",
    "Industry": "Technology"
});
let record_id = sobject_client.create("Account", data).await?;

// Read a record
let record = sobject_client.get("Account", &record_id, None).await?;

// Update a record
let update_data = json!({ "Industry": "Manufacturing" });
sobject_client.update("Account", &record_id, update_data).await?;

// Delete a record
sobject_client.delete("Account", &record_id).await?;
```

### Managed Event Subscriptions

```rust
use salesforce_core::tooling::{self, ManagedEventSubscriptionMetadata, ReplayPreset, SubscriptionState};
use salesforce_core::pubsub::{Client as PubSubClient, ManagedFetchRequest};

// Step 1: Create managed subscription via Tooling API
let tooling_client = tooling::ClientBuilder::new(auth_client.clone()).build();

let subscription = tooling::CreateManagedEventSubscriptionRequest {
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
let channel = tonic::transport::Channel::from_static(salesforce_core::pubsub::ENDPOINT)
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
- [Pub/Sub API](examples/salesforce-core/pubsub.rs)
- [Bulk API 2.0](examples/salesforce-core/bulkapi.rs)
- [Managed Event Subscriptions](examples/salesforce-core/managed_subscription.rs) - Create and consume managed subscriptions

## Project Structure

```
salesforce-rs/
├── salesforce-core/           # Core SDK
│   └── src/
│       ├── client.rs          # OAuth2 authentication
│       ├── pubsub/            # Pub/Sub API client
│       ├── bulkapi/           # Bulk API 2.0 client
│       ├── sobject/           # SObject REST API (CRUD)
│       ├── tooling/           # Tooling API (metadata operations)
│       └── http.rs            # Shared HTTP client utilities
├── generated/                 # Generated API code
│   ├── salesforce-core/v1/    # Bulk API 2.0 & SObject (OpenAPI)
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
| Describe SObject | ✓ |

### Tooling API

| Operation | Status |
|-----------|--------|
| Create Managed Event Subscription | ✓ |
| Get Managed Event Subscription | - |
| Update Managed Event Subscription | - |
| Delete Managed Event Subscription | - |

## License

MPL-2.0

---

This is an unofficial SDK and is not affiliated with or endorsed by Salesforce.
