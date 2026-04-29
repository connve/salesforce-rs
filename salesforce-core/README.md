# salesforce_core

[![Crates.io](https://img.shields.io/crates/v/salesforce_core.svg)](https://crates.io/crates/salesforce_core)
[![Docs.rs](https://docs.rs/salesforce_core/badge.svg)](https://docs.rs/salesforce_core)

Unofficial Rust SDK for the **Salesforce Core** (Sales Cloud, Service Cloud, Platform, etc.) APIs: REST, Bulk 2.0, Pub/Sub (gRPC), and Tooling.

Part of the [salesforce-rs](https://github.com/connve/salesforce-rs) project. Sibling crates for other Salesforce products (Marketing Cloud, Data Cloud, etc.) live in the same repo.

## Installation

```toml
[dependencies]
salesforce_core = "0.13"
```

## Quick start

Authenticate with the client credentials OAuth2 flow, then issue REST calls:

```rust
use salesforce_core::client;
use salesforce_core::restapi;
use serde_json::json;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = client::Builder::new()
        .credentials_path(PathBuf::from(std::env::var("SFDC_CREDENTIALS")?))
        .build()?
        .connect()
        .await?;

    let rest = restapi::ClientBuilder::new(auth).build()?;

    let resp = rest.create("Account", json!({ "Name": "Acme" })).await?;
    let record = rest.get("Account", &resp.id, None).await?;
    println!("{record}");
    rest.delete("Account", &resp.id).await?;

    Ok(())
}
```

The credentials JSON file:

```json
{
  "client_id": "...",
  "client_secret": "...",
  "instance_url": "https://your-instance.my.salesforce.com",
  "tenant_id": "..."
}
```

## API coverage

### Authentication

| Feature | Status |
|---------|--------|
| OAuth2 Client Credentials Flow | ✓ |
| OAuth2 Username-Password Flow | ✓ |
| Automatic Token Refresh | ✓ |
| Session Reconnection | ✓ |

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

### Bulk API 2.0 — Query

| Operation | Status |
|-----------|--------|
| Create Query Job | ✓ |
| Get Query Job Info | ✓ |
| Get Query Results | ✓ |
| Get Query Result Pages | ✓ |
| Get All Query Jobs | ✓ |
| Abort Query Job | ✓ |
| Delete Query Job | ✓ |

### Bulk API 2.0 — Ingest

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

### Tooling API

| Operation | Status |
|-----------|--------|
| Create Managed Event Subscription | ✓ |
| Get Managed Event Subscription | — |
| Update Managed Event Subscription | — |
| Delete Managed Event Subscription | — |

## Examples

See the [examples directory](https://github.com/connve/salesforce-rs/tree/main/examples/salesforce-core):

- [`restapi`](https://github.com/connve/salesforce-rs/blob/main/examples/salesforce-core/restapi.rs) — SObject CRUD operations
- [`bulkapi`](https://github.com/connve/salesforce-rs/blob/main/examples/salesforce-core/bulkapi.rs) — Query and ingest for large datasets
- [`toolingapi`](https://github.com/connve/salesforce-rs/blob/main/examples/salesforce-core/toolingapi.rs) — Managed event subscriptions
- [`pubsubapi`](https://github.com/connve/salesforce-rs/blob/main/examples/salesforce-core/pubsubapi.rs) — Platform events and CDC via gRPC

```bash
export SFDC_CREDENTIALS=$PWD/credentials.json
cargo run --example restapi
```

## License

MPL-2.0
