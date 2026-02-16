//! Unofficial Rust SDK for the Salesforce API.
//!
//! This crate provides authentication and Pub/Sub API support for Salesforce.
//!
//! # Examples
//!
//! ```no_run
//! use salesforce_core::client::{self, Credentials};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = client::Builder::new()
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

/// OAuth2 client authentication and connection management.
pub mod client;

/// Salesforce Pub/Sub API for real-time event streaming.
pub mod pubsub;

/// Salesforce Bulk API v2.0 for querying and ingesting large data sets.
pub mod bulkapi;
