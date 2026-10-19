# salesforce_core

[![Test Suite](https://github.com/connve/salesforce-rs/actions/workflows/test.yml/badge.svg)](https://github.com/connve/salesforce-rs/actions/workflows/test.yml)
[![Security Audit](https://github.com/connve/salesforce-rs/actions/workflows/security.yml/badge.svg)](https://github.com/connve/salesforce-rs/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/connve/salesforce-rs)](https://github.com/connve/salesforce-rs/releases)
[![Crates.io](https://img.shields.io/crates/v/salesforce_core.svg)](https://crates.io/crates/salesforce_core)
[![Docs.rs](https://docs.rs/salesforce_core/badge.svg)](https://docs.rs/salesforce_core)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

Unofficial Rust SDK for the **Salesforce Core** (Sales Cloud, Service Cloud, Platform) APIs: REST, Bulk 2.0, Pub/Sub (gRPC), Tooling, and SOAP.

> Not affiliated with or endorsed by Salesforce, Inc.

Part of the [salesforce-rs](https://github.com/connve/salesforce-rs) project.

## Quick start

```toml
[dependencies]
salesforce_core = "0.23"
```

```rust
use salesforce_core::{client, restapi};
use serde_json::json;

let auth = client::Client::builder()
    .client_id(client_id)
    .client_secret(client_secret)
    .instance_url("https://your-instance.my.salesforce.com")
    .build()?
    .connect()
    .await?;

let rest = restapi::ClientBuilder::new(auth).build()?;

let created = rest.create("Account", json!({ "Name": "Acme" })).send().await?;
let record = rest.get("Account", &created.id).send().await?;
rest.delete("Account", &created.id).send().await?;
```

## Credentials

The client authenticates against a Connected App with the client credentials
flow, or with `AuthFlow::UsernamePassword`. Set each field on
`client::Builder`, or pass a `Credentials` the application has loaded.
`Credentials` deserializes from JSON:

```json
{
  "client_id": "...",
  "client_secret": "...",
  "instance_url": "https://your-instance.my.salesforce.com",
  "tenant_id": "..."
}
```

```rust
let credentials: client::Credentials = serde_json::from_str(&json)?;
let auth = client::Client::builder().credentials(credentials).build()?;
```

`tenant_id` (the org ID) is only needed for the Pub/Sub API. `username` and
`password` are only needed for the username-password flow.

## SOQL values

The REST and Bulk APIs have no bind variables, so values go into the query
as literals. Write them with the `soql` helpers, so a value can't change the
query:

```rust
use salesforce_core::soql;

let query = format!(
    "SELECT Id FROM Contact WHERE LastName = {} AND Email LIKE {} AND Id IN {} AND CreatedDate > {}",
    soql::quote(last_name),
    soql::like_ends_with("@example.com"),
    soql::quote_list(&ids).ok_or("no ids")?,
    soql::datetime(since),
);
```

| Helper | Writes |
| --- | --- |
| `quote` | String literal: `'O\'Brien'` |
| `like_contains`, `like_starts_with`, `like_ends_with` | `LIKE` pattern with `%` and `_` in the value matched literally |
| `quote_list` | `IN` list: `('a', 'b')`; `None` when empty |
| `date`, `datetime` | `2026-10-19`, `2026-10-19T12:00:00Z` |

## Pagination

SOQL queries return one batch at a time. Pass `next_records_url` to
`query_more` until it is `None`:

```rust
let mut page = rest.query("SELECT Id FROM Account").send().await?;
while let Some(next) = page.next_records_url.take() {
    page = rest.query_more(next).send().await?;
}
```

Bulk query results come in pages too. `result_pages` follows the
`Sforce-Locator` header until the last page:

```rust
let mut pages = bulk.query().result_pages(&job.id, None);
while let Some(page) = pages.next_page().await {
    let csv = page?.body; // stream of bytes
}
```

## Request headers

REST and Composite builders take Salesforce request headers before `.send()`:

```rust
rest.create("Account", json!({ "Name": "Acme" }))
    .header("Sforce-Duplicate-Rule-Header", "allowSave=true")
    .send()
    .await?;
```

Headers for every request go on the client with
`restapi::ClientBuilder::default_headers`. `Authorization`, `Content-Type`,
and `Accept` are set by the SDK and rejected with `Error::InvalidHeader`.

## Cargo features

All features except `trace` are enabled by default. For a slim build, turn
off the defaults and pick what you need:

```toml
salesforce_core = { version = "0.23", default-features = false, features = ["restapi"] }
```

`chrono` is re-exported as `salesforce_core::chrono`. Use it for the
`DateTime<Utc>` arguments, such as the window passed to `get_deleted`.

## Coverage

| API | Feature | Methods |
| --- | --- | --- |
| Auth | (always) | `client::Builder`, `connect`, `access_token`, `reconnect` |
| SObject | `restapi` | [`create`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_basic_info_post.htm), [`get`](https://developer.salesforce.com/docs/platform/api-rest/guide/resources-sobject-retrieve.html), [`get_by_external_id`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_upsert.htm), [`update`](https://developer.salesforce.com/docs/platform/api-rest/guide/resources-sobject-retrieve-patch.html), [`delete`](https://developer.salesforce.com/docs/platform/api-rest/guide/dome-delete-record.html), [`get_deleted`](https://developer.salesforce.com/docs/platform/api-rest/guide/resources-getdeleted.html), [`describe`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_describe.htm), [`basic_info`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_basic_info.htm) |
| Composite | `restapi` | [`create_records`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_composite_sobjects_collections_create.htm), [`get_records`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_composite_sobjects_collections_retrieve.htm), [`update_records`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_composite_sobjects_collections_update.htm), `upsert_records`, [`delete_records`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_composite_sobjects_collections_delete.htm), [`create_record_tree`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_composite_sobject_tree.htm) |
| Query | `restapi` | [`query`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_query.htm), [`query_all`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_queryall.htm), [`query_more`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_query_more_results.htm) |
| Search | `restapi` | [`search`](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_search.htm) |
| Flow | `restapi` | [`invoke_flow`](https://developer.salesforce.com/docs/platform/api-rest/guide/resources-actions-invocable-custom.html), [`invoke_flow_batch`](https://developer.salesforce.com/docs/platform/api-rest/guide/resources-actions-invocable-custom.html) |
| Bulk 2.0 query | `bulkapi` | [`create_job`](https://developer.salesforce.com/docs/platform/api-asynch/guide/query-create-job.html), [`get_job`](https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-one-job.html), `get_results`, `result_pages`, `get_result_pages`, `get_all_jobs`, [`abort_job`](https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/query_abort_job.htm), [`delete_job`](https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/delete_job.htm) |
| Bulk 2.0 ingest | `bulkapi` | [`create_job`](https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm), [`get_job`](https://developer.salesforce.com/docs/platform/api-asynch/guide/get-job-info.html), `upload_data`, [`mark_upload_complete`](https://developer.salesforce.com/docs/platform/api-asynch/guide/close-job.html), `get_successful_results`, [`get_failed_results`](https://developer.salesforce.com/docs/platform/api-asynch/guide/get-job-failed-results.html), `get_unprocessed_results`, [`get_all_jobs`](https://developer.salesforce.com/docs/platform/api-asynch/guide/get-all-jobs.html), `abort_job`, [`delete_job`](https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/delete_job.htm) |
| Pub/Sub (gRPC) | `pubsubapi` | [`get_topic`](https://developer.salesforce.com/docs/platform/pub-sub-api/references/methods/gettopic-rpc.html), `get_schema`, [`subscribe`](https://developer.salesforce.com/docs/platform/pub-sub-api/references/methods/subscribe-rpc.html), [`managed_subscribe`](https://developer.salesforce.com/docs/platform/pub-sub-api/references/methods/managedsubscribe-rpc.html), `publish`, [`publish_stream`](https://developer.salesforce.com/docs/platform/pub-sub-api/references/methods/publishstream-rpc.html) |
| SOAP | `soapapi` | [`merge`](https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce_api_calls_merge.htm) |
| Tooling | `toolingapi` | [`create_managed_event_subscription`](https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/tooling_api_objects_managedeventsubscription.htm) |

The `trace` feature adds `tracing` spans to client methods.

## Examples

Runnable examples live in
[`examples/salesforce-core`](https://github.com/connve/salesforce-rs/tree/main/examples/salesforce-core).
They read the credentials JSON from the path in `SFDC_CREDENTIALS`:

```bash
export SFDC_CREDENTIALS=$PWD/credentials.json
cargo run --example restapi
```

## License

MPL-2.0
