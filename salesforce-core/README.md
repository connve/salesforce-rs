# salesforce_core

[![Crates.io](https://img.shields.io/crates/v/salesforce_core.svg)](https://crates.io/crates/salesforce_core)
[![Docs.rs](https://docs.rs/salesforce_core/badge.svg)](https://docs.rs/salesforce_core)

Unofficial Rust SDK for the **Salesforce Core** (Sales Cloud, Service Cloud, Platform) APIs: REST, Bulk 2.0, Pub/Sub (gRPC), Tooling, and SOAP.

Part of the [salesforce-rs](https://github.com/connve/salesforce-rs) project.

## Installation

```toml
[dependencies]
salesforce_core = "0.18"
```

## Cargo features

Each API surface is gated behind a feature so applications only pay the
compile-time cost of what they use. All four are enabled by default.

| Feature      | Enables                                                      |
|--------------|--------------------------------------------------------------|
| `restapi`    | SObject CRUD, search, composite collections, flow invocation (REST API) |
| `bulkapi`    | Bulk API 2.0 query and ingest jobs                           |
| `toolingapi` | Tooling API (managed event subscriptions)                    |
| `pubsubapi`  | Pub/Sub API gRPC streaming (pulls in `tonic`)                |
| `soapapi`    | SOAP API operations (record merge)                           |
| `trace`      | Adds `#[tracing::instrument]` spans to client methods        |

For a slim build, disable defaults and opt in:

```toml
salesforce_core = { version = "0.18", default-features = false, features = ["restapi"] }
```

`chrono` appears in the public API — operations taking a time window accept
`DateTime<Utc>`. It is re-exported as `salesforce_core::chrono`, so use that
rather than adding `chrono` to your own dependencies:

```rust
use salesforce_core::chrono::{Duration, Utc};

let end = Utc::now();
let deleted = rest.get_deleted("Account", (end - Duration::days(1))..end).send().await?;
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

    let resp = rest.create("Account", json!({ "Name": "Acme" })).send().await?;
    let record = rest.get("Account", &resp.id).send().await?;
    println!("{record}");
    rest.delete("Account", &resp.id).send().await?;

    Ok(())
}
```

## Salesforce request headers

Every REST and Composite operation returns a builder that accepts custom
Salesforce request headers via `.header(name, value)` or `.headers(map)`,
then is dispatched with `.send().await`:

```rust,no_run
use salesforce_core::restapi;
use serde_json::json;

# async fn run(rest: restapi::Client) -> Result<(), Box<dyn std::error::Error>> {
// Override the duplicate rule for a single create:
let resp = rest
    .create("Account", json!({ "Name": "Acme" }))
    .header("Sforce-Duplicate-Rule-Header", "allowSave=true")
    .send()
    .await?;

// Or attach several headers, e.g. on a composite update:
# let request: salesforce_core::restapi::CompositeCollectionUpdateRequest = todo!();
let _ = rest
    .composite()
    .update_records(&request)
    .header("Sforce-Duplicate-Rule-Header", "allowSave=true")
    .header("Sforce-Auto-Assign", "FALSE")
    .send()
    .await?;
# Ok(())
# }
```

The SDK rejects headers it manages itself (`Authorization`, `Content-Type`,
`Accept`) at `.send()` time with `Error::InvalidHeader`.

To send the same headers on every request issued by a client, configure them
once on the builder instead:

```rust,no_run
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use salesforce_core::restapi;

# fn build(auth: salesforce_core::client::Client) -> Result<(), Box<dyn std::error::Error>> {
let mut defaults = HeaderMap::new();
defaults.insert(
    HeaderName::from_static("sforce-call-options"),
    HeaderValue::from_static("client=my-app"),
);

let rest = restapi::ClientBuilder::new(auth)
    .default_headers(defaults)
    .build()?;
# let _ = rest;
# Ok(())
# }
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
| OAuth2 Client Credentials Flow | Supported |
| OAuth2 Username-Password Flow | Supported |
| Automatic Token Refresh | Supported |
| Session Reconnection | Supported |

### SObject REST API

| Operation | Status |
|-----------|--------|
| Create Record | Supported |
| Get Record | Supported |
| Get Record by External ID | Supported |
| Update Record | Supported |
| Delete Record | Supported |
| Get Deleted Records | Supported |
| Get SObject Basic Info | Supported |
| Describe SObject | Supported |

### Composite REST API

| Operation | Status |
|-----------|--------|
| Create Records (batch) | Supported |
| Update Records (batch) | Supported |
| Delete Records (batch) | Supported |
| Retrieve Records (batch) | Supported |
| Upsert Records (batch) | Supported |
| Create Record Tree | Supported |

### Search

| Operation | Status |
|-----------|--------|
| SOSL Search | Supported |

### Custom Invocable Actions — Flow

| Operation | Status |
|-----------|--------|
| Invoke Flow (single input) | Supported |
| Invoke Flow (batch / multiple inputs) | Supported |

### Bulk API 2.0 — Query

| Operation | Status |
|-----------|--------|
| Create Query Job | Supported |
| Get Query Job Info | Supported |
| Get Query Results | Supported |
| Get Query Result Pages | Supported |
| Get All Query Jobs | Supported |
| Abort Query Job | Supported |
| Delete Query Job | Supported |

### Bulk API 2.0 — Ingest

| Operation | Status |
|-----------|--------|
| Create Ingest Job | Supported |
| Get Ingest Job Info | Supported |
| Upload Job Data | Supported |
| Mark Upload Complete | Supported |
| Get Successful Results | Supported |
| Get Failed Results | Supported |
| Get Unprocessed Results | Supported |
| Get All Ingest Jobs | Supported |
| Abort Ingest Job | Supported |
| Delete Ingest Job | Supported |

### Pub/Sub API (gRPC)

| Operation | Status |
|-----------|--------|
| Get Topic | Supported |
| Get Schema | Supported |
| Subscribe | Supported |
| Managed Subscribe | Supported |
| Publish | Supported |
| Publish Stream | Supported |
| Get Topic by Schema ID | Supported |

### SOAP API

| Operation | Status |
|-----------|--------|
| Merge Records | Supported |

### Tooling API

| Operation | Status |
|-----------|--------|
| Create Managed Event Subscription | Supported |

## Examples

See the [examples directory](https://github.com/connve/salesforce-rs/tree/main/examples/salesforce-core):

- [`restapi`](https://github.com/connve/salesforce-rs/blob/main/examples/salesforce-core/restapi.rs) — SObject CRUD operations
- [`bulkapi`](https://github.com/connve/salesforce-rs/blob/main/examples/salesforce-core/bulkapi.rs) — Query and ingest for large datasets
- [`toolingapi`](https://github.com/connve/salesforce-rs/blob/main/examples/salesforce-core/toolingapi.rs) — Managed event subscriptions
- [`pubsubapi`](https://github.com/connve/salesforce-rs/blob/main/examples/salesforce-core/pubsubapi.rs) — Platform events and CDC via gRPC
- [`soapapi`](https://github.com/connve/salesforce-rs/blob/main/examples/salesforce-core/soapapi.rs) — Record merge via SOAP API

```bash
export SFDC_CREDENTIALS=$PWD/credentials.json
cargo run --example restapi
```

## License

MPL-2.0
