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

## What's included

- **OAuth2** — client credentials flow, username-password flow, automatic token refresh
- **REST API** — SObject CRUD, describe, basic info, SOSL search
- **Composite REST API** — batch create/update/delete/retrieve, upsert, record trees
- **Bulk API 2.0** — query and ingest jobs for large datasets
- **Pub/Sub API (gRPC)** — platform events, Change Data Capture, managed subscriptions
- **Tooling API** — managed event subscription metadata

For the full API reference and examples, see the [project README](https://github.com/connve/salesforce-rs#readme) and the [examples directory](https://github.com/connve/salesforce-rs/tree/main/examples).

## License

MPL-2.0
