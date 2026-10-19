# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.22.0]

### Changed
- The README shows the same badges on GitHub and crates.io.

## [0.21.0]

### Changed
- **Breaking:** `bulkapi::QueryClient::get_results` returns `QueryResults` (`body`, `locator`, `number_of_records`) instead of a `ByteStream`.
  Before: `let stream = query.get_results(id, None, None).await?;`
  After: `let stream = query.get_results(id, None, None).await?.body;`
- **Breaking:** `client::Builder::credentials_path` is removed. The SDK no longer reads files; load the JSON in your application and pass it to `.credentials()`.
  Before: `.credentials_path(path)`
  After: `.credentials(serde_json::from_str(&std::fs::read_to_string(path)?)?)`
- **Breaking:** `Credentials::tenant_id` is `Option<String>`. Only the Pub/Sub API needs it.
- **Breaking:** `client::Builder::build` checks the fields the auth flow needs and that `instance_url` is an absolute URL. Missing fields fail at `build()` instead of `connect()`.
- **Breaking:** Removed `client::CredentialsFrom` and the `ReadCredentials`, `ParseCredentials`, and `MissingCredentials` errors.
- `salesforce_core` pins the generated crates with `=x.y.z`.
- `CONTRIBUTORS.md` is renamed to `CONTRIBUTING.md`, and the development notes moved there from the README.

### Added
- `bulkapi::QueryClient::result_pages` returns `Pages`, which walks every result page with `next_page().await`. A failed page is retried on the next call.
- `client::Client::builder()`. `client::Builder::new()` still works.
- `client::Builder` setters: `client_id`, `client_secret`, `username`, `password`, `instance_url`, `tenant_id`.
- `client::Error::MissingClientId` and `MissingInstanceUrl`.

### Fixed
- Bulk query results past the first page couldn't be read, because `get_results` dropped the `Sforce-Locator` header.

## [0.20.1]

### Fixed
- `salesforce_core_pubsubapi` didn't build on its own, so 0.20.0 was only partly published. It now enables `serde/std` directly.

## [0.20.0]

### Changed
- **Breaking:** `Credentials::client_secret` and `password` are `Option<SecretString>`. `Credentials` no longer implements `Serialize`.
- **Breaking:** `Client::access_token()` and `current_access_token()` return `SecretString`.
- **Breaking:** `.headers(map)` on REST builders merges into existing headers instead of replacing them.
- **Breaking:** `.header(name, value)` requires `name: AsRef<str>`; invalid names are reported as given.
- **Breaking:** `bulkapi::QueryClient::get_results` takes `max_records: Option<NonZeroU64>`.
- **Breaking:** `CompositeError::HttpClient` and `QueryError::HttpClient` hold a `reqwest::Error`; auth failures go to `Auth`.
- `Content-Length`, `Transfer-Encoding`, and `Host` are rejected as REST headers.
- REST and Bulk reject empty, `.`, `..`, or control-character path segments with `InvalidPathSegment`.
- Access tokens and the `Authorization` header are redacted from `Debug` output.
- `is_retryable()` docs on `SObjectError`, `CompositeError`, and `FlowError` warn that retried creates and flows can run twice.
- Removed unused dependencies from the generated crates.

### Added
- `salesforce_core::header` (re-export of `reqwest::header`) and `salesforce_core::secrecy`.
- `client::Error::InvalidAccessToken`.

### Fixed
- `soapapi::Client::merge` escapes `sobject_type` and `master_record_id` and rejects invalid field names with `InvalidFieldName`, closing an XML injection.
- SObject, Composite, and Query reuse the cached HTTP client instead of building one per call.
- Per-call REST headers replace default headers of the same name instead of being sent alongside them.
- An invalid access token is reported as `InvalidAccessToken` instead of `LockError`; a poisoned client cache no longer fails later requests.
- `get_results` no longer turns a negative `max_records` into a huge limit.

## [0.19.0]

### Added
- `restapi::Client::query(soql)` executes a SOQL query via `GET /query` and returns the first batch of results. It works against any queryable object, so custom settings and custom metadata types (`SELECT Name, Value__c FROM My_Setting__c`) can now be read through the SDK.
- `restapi::Client::query_all(soql)` executes the same query via `GET /queryAll`, which also returns records in the Recycle Bin, records removed by a merge, and archived activities.
- `restapi::Client::query_more(next_records_url)` fetches the next batch when a response has `done: false`. It accepts the response's `next_records_url` as returned, or the bare query locator, and covers `query_all` pagination too, since Salesforce serves both through `/query/{queryLocator}`.
- All three return builders (`restapi::query::{Query, QueryAll, QueryMore}`) dispatched with `.send().await`, with the same `.header()` / `.headers()` plumbing as the SObject and Composite operations; set `Sforce-Query-Options: batchSize=<n>` to change the batch size.
- `restapi::QueryResponse` (`total_size`, `done`, `next_records_url`, `records`) re-exported from the generated client, and `restapi::QueryError`, whose `InvalidNextRecordsUrl` variant is returned by `QueryMore::send()` without issuing a request when no query locator can be extracted.

### Changed
- `DEFAULT_API_VERSION` is now `68.0` (Winter '27), up from `65.0` (Winter '26). Every client built without `.api_version(...)` (REST, Bulk 2.0, Tooling, SOAP) now targets v68.0, as do the server defaults in the bundled OpenAPI specs. Winter '27 finished rolling out to production orgs on 2026-10-09; to keep the previous behaviour, pin it with `.api_version("65.0")` on the client builder.

## [0.18.0]

### Added
- `restapi::Client::get_deleted(sobject_type, start..end)` retrieves the IDs and deletion datetimes of records deleted within a time window, via `GET /sobjects/{sObjectType}/deleted`. The window is a `Range<DateTime<Utc>>`, so it reads directionally at the call site and carries the half-open `[start, end)` semantics the endpoint already has. Returns a `GetDeleted` builder dispatched with `.send().await`, supporting the same per-call `.header()` / `.headers()` plumbing as the other SObject operations.
- `restapi::{DeletedRecord, GetDeletedRecordsResponse}` re-exported from the generated client. The response carries `deleted_records`, `earliest_date_available`, and `latest_date_covered`.
- `chrono` is now a direct dependency of `salesforce_core`; `get_deleted` takes `DateTime<Utc>` bounds rather than pre-formatted strings. It is re-exported as `salesforce_core::chrono`, so callers can build those values without declaring their own `chrono` dependency and risking a version mismatch with the one the SDK was built against.
- `restapi::sobject::Error::InvalidTimeWindow { start, end }` is returned by `GetDeleted::send()` when `end` is not after `start`, without issuing a request. Salesforce's remaining constraints (retention cut-off, the 600,000-record `EXCEEDED_ID_LIMIT`, `end` in the future) stay server-side, since they vary by org and over time; read `earliest_date_available` from the response rather than assuming a fixed retention figure.

### Changed
- Workspace lints are now declared centrally in `[workspace.lints.clippy]` and opted into by `salesforce-core`: `clippy::all` is denied, and `allow_attributes` / `allow_attributes_without_reason` require suppressions to be written as `#[expect(lint, reason = "...")]`. Because clippy reports an `#[expect]` that no longer applies, obsolete suppressions surface instead of lingering silently.
- Removed a crate-wide `#![allow(clippy::result_large_err)]` from `lib.rs` and `#[allow(clippy::type_complexity)]` from `client::Client`, and finished the boxing that 0.17.0 began: `restapi::search::Error::SearchApi`, `restapi::flow::Error::FlowApi`, `bulkapi::ingest::Error::BulkApi`, and `bulkapi::query::Error::BulkApi` now box their `GeneratedError` source, matching `restapi::sobject` and `restapi::composite`. The variants still expose the same `#[source]` accessor, so this is not a breaking change.

## [0.17.0]

### Added
- Per-call Salesforce request headers on every REST and Composite operation via a reqwest-style request builder. Each method now returns a dedicated builder type that supports `.header(name, value)` / `.headers(map)` and is dispatched with `.send().await`. This unblocks `Sforce-Duplicate-Rule-Header: allowSave=true` and any other Salesforce request header (`Sforce-Auto-Assign`, `Sforce-Call-Options`, `Sforce-Mru`, …).
  - `restapi::sobject::{Create, Get, GetByExternalId, Update, Delete, Describe, BasicInfo}`
  - `restapi::composite::{CreateRecords, GetRecords, UpdateRecords, UpsertRecords, DeleteRecords, CreateRecordTree}`
- `restapi::ClientBuilder::default_headers(HeaderMap)` — set Salesforce headers once per client; per-call headers merge on top.
- `is_retryable()` on the three remaining public `Error` enums missed by 0.16.0: `restapi::client::Error`, `bulkapi::client::Error`, `soapapi::client::Error`. All three are builder/config errors and report `false`. Closes the §6 (CONTRIBUTORS.md) uniformity gap.
- `restapi::sobject::Error::InvalidHeader { name }` and `restapi::composite::Error::InvalidHeader { name }` surface reserved-name or invalid-value rejections at `.send()` time.

### Changed
- **Breaking:** `restapi::sobject` and `restapi::composite` operations now return a builder instead of being directly `await`able. Migration is mechanical:
  - `rest.create("Account", data).await?` → `rest.create("Account", data).send().await?`
  - `rest.get("Account", id, Some("Id,Name"))` → `rest.get("Account", id).fields("Id,Name").send()`
  - `rest.delete_records(ids, Some(false))` → `rest.delete_records(ids).all_or_none(false).send()`
- `http::Error` is now `#[non_exhaustive]`. The module is `pub(crate)`, so this is not a downstream-visible change.
- HTTP client cache key extended with a stable hash over the client-level header set; cached clients are reused only when both the bearer token and the configured default headers are unchanged.
- `restapi::sobject::Error::SObjectApi` and `restapi::composite::Error::CompositeApi` now box their `GeneratedError` source to keep the enums small (clippy `result_large_err`).
- The `trace` feature now activates `tracing/attributes`, so `--features trace` builds work in any feature combination (previously slim builds without `pubsubapi` failed to find `tracing::instrument`).
- `#[cfg_attr(feature = "trace", tracing::instrument(skip_all))]` is now applied uniformly to every public async method across `restapi`, `bulkapi`, `pubsubapi`, `soapapi`, `toolingapi`, and `client`.
- The `bulkapi` feature now activates `futures-util` (previously gated only behind `pubsubapi`). Consumers of `bulkapi::ByteStream` need `StreamExt` to drive the stream, so a `--features bulkapi` build now compiles standalone — including the example.

## [0.16.0]

### Added
- `is_retryable(&self) -> bool` method on every public `Error` enum in `salesforce_core`. Consumers (e.g. flowgen) can now collapse retry classification to a single call instead of pattern-matching on inner progenitor / tonic types. Added on: `client::Error`, `http::Error`, `pubsubapi::Error`, `toolingapi::Error`, `soapapi::merge::Error`, `restapi::search::Error`, `restapi::sobject::Error`, `restapi::composite::Error`, `restapi::flow::Error`, `bulkapi::ingest::Error`, `bulkapi::query::Error`.
- REST wrapper enums proxy to `progenitor_client::Error::is_retryable()` (429, 502, 503, 504, and communication errors are retryable).
- `pubsubapi::Error::is_retryable()` classifies gRPC status codes: `Cancelled`, `InvalidArgument`, `NotFound`, `AlreadyExists`, `PermissionDenied`, `FailedPrecondition`, `OutOfRange`, `Unimplemented`, and `Unauthenticated` are non-retryable; all other `Tonic` statuses are transient.
- `toolingapi::Error::ApiError` and `client::Error::OAuth2RequestFailed` are retryable on HTTP 429 or 5xx; configuration variants (missing credentials, parse errors, etc.) are never retryable.
- `soapapi::merge::Error::MergeApi` is retryable on 429/5xx unless the SOAP `<faultcode>` is `sf:`-prefixed (e.g. `sf:INVALID_FIELD`), which indicates a permanent client error regardless of HTTP status.

### Changed
- **Breaking:** `soapapi::merge::Error::MergeApi` variant shape changed from `{ message: String }` to `{ status: u16, fault_code: Option<String>, message: String }` so callers can distinguish transient 5xx faults from permanent SOAP faults. The merge call site now extracts `<faultcode>` alongside the existing `<faultstring>`.

## [0.15.0]

### Added
- `restapi::Client::invoke_flow()` — invoke an autolaunched Salesforce Flow via the Custom Invocable Actions REST endpoint (`POST /actions/custom/flow/{flowApiName}`). Accepts a single JSON object of input variables.
- `restapi::Client::invoke_flow_batch()` — batch variant that accepts multiple sets of input variables, launching a separate flow interview per set.
- `FlowInvokeRequest`, `FlowInvokeResponse`, `FlowInvokeResult`, `FlowError` types exported from `salesforce_core::restapi`.
- Integration tests for flow invocation (invalid name, batch, input type validation).

### Fixed
- `client::Client::reconnect()` now writes into the existing `RwLock<TokenState>` instead of replacing the `Arc`. Previously, cloned clients (held by `restapi::Client`, `bulkapi::Client`, etc.) would keep a stale token after the original client reconnected.

## [0.14.0]

### Added
- `soapapi` module — new feature-gated module for Salesforce SOAP API operations not available through the REST API.
- `soapapi::Client::merge()` — merge up to three SObject records (Account, Contact, Lead, Individual) into a single master record with optional field overrides.
- `MergeResponse`, `ClientBuilder`, `Client`, `ClientError`, `MergeError` types exported from `salesforce_core::soapapi`.
- `allow_duplicate_save` parameter on `soapapi::Client::merge()` to bypass duplicate detection rules via `DuplicateRuleHeader`.

### Changed
- Release workflow now extracts changelog entries for GitHub Release notes instead of using the last commit message. Falls back to git log when no CHANGELOG.md section exists for the version.

## [0.13.6]

### Added
- Cargo features `restapi`, `bulkapi`, `toolingapi`, `pubsubapi` to gate each API surface so users can opt out of unused generated clients (and, for `pubsubapi`, the `tonic`/`futures-util` gRPC stack). All four are enabled by default — existing users see no change. Slim builds use `default-features = false` and opt in to only what they need.

### Changed
- Per-API doctest blocks moved out of the crate root in `lib.rs`; module-level docs already carry the same examples and now drop out of the build cleanly when their feature is disabled.
- `tests/bulkapi.rs` imports `CreateQueryJobRequest`/`QueryOperation` from `salesforce_core::bulkapi` instead of the (now optional) generated crate.

## [0.13.5]

### Fixed
- docs.rs builds for the generated crates (`salesforce_core_bulkapi`, `salesforce_core_restapi`, `salesforce_core_toolingapi`, `salesforce_core_pubsubapi`). Build scripts now emit generated code into `OUT_DIR` instead of writing back into `src/`, which fails on docs.rs's read-only sandbox.

### Removed
- Committed `src/generated.rs` files in the four generated crates (and `src/eventbus.v1.rs` in `pubsubapi`). They were build-script outputs that no longer need to be tracked in git.

## [0.13.4]

### Added
- `restapi::Client::basic_info()` — `GET /sobjects/{type}` returning recently viewed records.
- `SObjectBasicInfo` and `SObjectMetadata` types in the generated REST client.
- Integration test suite for auth, REST, composite, and Bulk APIs.
- CI integration-test job that runs against a real Salesforce org via `SFDC_CREDENTIALS`.
- Per-crate README for `salesforce_core` so the crates.io page is focused on the Core APIs only.
- `rust-version = "1.88"` (MSRV) declared at the workspace level.
- Crate metadata required for crates.io publishing (`description`, `keywords`, `categories`, `documentation`, `readme`).

### Changed
- Split `GET /sobjects/{sObjectType}` in the REST OpenAPI spec into two endpoints: `getSobjectBasicInfo` (basic info) and `describeSobject` at `/sobjects/{type}/describe` (full describe). The previous path was wrong, causing describe responses to fail to deserialize against real orgs.
- `composite/tree/{sObjectType}` now correctly accepts `201 Created` (was `200`).
- `composite/sobjects/{type}/{externalIdField}` upsert now accepts both `200` and `201`.
- All examples switched from individual `SALESFORCE_*` env vars to a single `SFDC_CREDENTIALS` JSON file path.
- OpenAPI `operationId` casing convention adopted (single-capital prefixes for acronyms) so `progenitor` generates clean snake_case method names — e.g. `describe_sobject` instead of `describe_s_object`.
- `http::Error::LockError` renamed to `http::Error::Lock` to satisfy clippy's `enum_variant_names` lint.
- Workspace path-deps moved into `[workspace.dependencies]` so versions live in one place.
