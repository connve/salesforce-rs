# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.5] - 2026-04-29

### Fixed
- docs.rs builds for the generated crates (`salesforce_core_bulkapi`, `salesforce_core_restapi`, `salesforce_core_toolingapi`, `salesforce_core_pubsubapi`). Build scripts now emit generated code into `OUT_DIR` instead of writing back into `src/`, which fails on docs.rs's read-only sandbox.

### Removed
- Committed `src/generated.rs` files in the four generated crates (and `src/eventbus.v1.rs` in `pubsubapi`). They were build-script outputs that no longer need to be tracked in git.

## [0.13.4] - 2026-04-28

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
