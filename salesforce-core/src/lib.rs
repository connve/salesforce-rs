//! Unofficial Rust SDK for the Salesforce API.
//!
//! This crate provides comprehensive support for Salesforce APIs including:
//! - OAuth2 authentication (client credentials and username-password flows)
//! - Pub/Sub API for real-time event streaming via gRPC
//! - Bulk API 2.0 for high-performance query and ingest operations
//! - REST API for SObject CRUD operations
//! - Tooling API for metadata and Change Data Capture subscriptions
//! - SOAP API for merge and other SOAP-only operations
//!
//! # Quick Start
//!
//! ## Authentication
//!
//! ```no_run
//! use salesforce_core::client::{self, Credentials};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let auth_client = client::Builder::new()
//!     .credentials(Credentials {
//!         client_id: "...".to_string(),
//!         client_secret: Some("...".to_string()),
//!         username: None,
//!         password: None,
//!         instance_url: "https://your-instance.salesforce.com".to_string(),
//!         tenant_id: "...".to_string(),
//!     })
//!     .build()?
//!     .connect()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! See module-level docs for per-API examples: [`restapi`], [`bulkapi`],
//! [`toolingapi`], [`pubsubapi`], [`soapapi`].
//!
//! # Cargo features
//!
//! Each API surface is gated behind a feature so applications only pay the
//! compile-time cost of what they use. All four are enabled by default.
//!
//! - `restapi` — SObject CRUD, search, composite collections (REST API)
//! - `bulkapi` — Bulk API 2.0 query and ingest jobs
//! - `toolingapi` — Tooling API (managed event subscriptions)
//! - `pubsubapi` — Pub/Sub API gRPC streaming (pulls in `tonic`)
//! - `soapapi` — SOAP API for merge and other SOAP-only operations
//! - `trace` — adds `#[tracing::instrument]` spans to client methods
//!
//! For a slim build, disable defaults and opt in:
//!
//! ```toml
//! salesforce_core = { version = "0.13", default-features = false, features = ["restapi"] }
//! ```

/// Default Salesforce API version (Winter '26 - API version 65.0).
pub const DEFAULT_API_VERSION: &str = "65.0";

/// Default connection timeout for HTTP requests (30 seconds).
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Default request timeout for HTTP requests (120 seconds).
///
/// This longer timeout is appropriate for bulk operations which may take longer to process.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 120;

/// Default connection timeout for OAuth2 authentication requests (15 seconds).
pub const DEFAULT_AUTH_CONNECT_TIMEOUT_SECS: u64 = 15;

/// Default request timeout for OAuth2 authentication requests (30 seconds).
pub const DEFAULT_AUTH_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default TCP keepalive interval (60 seconds).
pub const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 60;

/// Default connection pool idle timeout (90 seconds).
pub const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 90;

/// Default maximum idle connections per host (10).
pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 10;

/// OAuth2 client authentication and connection management.
pub mod client;

/// Salesforce Pub/Sub API for real-time event streaming.
#[cfg(feature = "pubsubapi")]
pub mod pubsubapi;

/// Salesforce Bulk API 2.0 for querying and ingesting large data sets.
#[cfg(feature = "bulkapi")]
pub mod bulkapi;

/// Salesforce REST API for SObject operations, queries, and searches.
#[cfg(feature = "restapi")]
pub mod restapi;

/// Salesforce Tooling API for metadata operations.
#[cfg(feature = "toolingapi")]
pub mod toolingapi;

/// Salesforce SOAP API for operations not available through the REST API.
#[cfg(feature = "soapapi")]
pub mod soapapi;

/// Shared HTTP client utilities.
#[cfg(any(
    feature = "restapi",
    feature = "bulkapi",
    feature = "toolingapi",
    feature = "soapapi"
))]
pub(crate) mod http;
