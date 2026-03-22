//! Unofficial Rust SDK for the Salesforce API.
//!
//! This crate provides comprehensive support for Salesforce APIs including:
//! - OAuth2 authentication (client credentials and username-password flows)
//! - Pub/Sub API for real-time event streaming via gRPC
//! - Bulk API 2.0 for high-performance query and ingest operations
//! - REST API for SObject CRUD operations
//! - Tooling API for metadata and Change Data Capture subscriptions
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
//! ## SObject REST API
//!
//! ```no_run
//! use salesforce_core::client::{self, Credentials};
//! use salesforce_core::restapi::ClientBuilder;
//! use serde_json::json;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let auth_client = client::Builder::new()
//! #     .credentials(Credentials {
//! #         client_id: "...".to_string(),
//! #         client_secret: Some("...".to_string()),
//! #         username: None,
//! #         password: None,
//! #         instance_url: "https://localhost".to_string(),
//! #         tenant_id: "...".to_string(),
//! #     })
//! #     .build()?
//! #     .connect()
//! #     .await?;
//! let rest_client = ClientBuilder::new(auth_client).build()?;
//!
//! // Create a record
//! let data = json!({
//!     "Name": "Acme Corporation",
//!     "Industry": "Technology"
//! });
//! let record_id = rest_client.create("Account", data).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Bulk API 2.0
//!
//! ```no_run
//! use salesforce_core::client::{self, Credentials};
//! use salesforce_core::bulkapi::{ClientBuilder, CreateQueryJobRequest, QueryOperation};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let auth_client = client::Builder::new()
//! #     .credentials(Credentials {
//! #         client_id: "...".to_string(),
//! #         client_secret: Some("...".to_string()),
//! #         username: None,
//! #         password: None,
//! #         instance_url: "https://localhost".to_string(),
//! #         tenant_id: "...".to_string(),
//! #     })
//! #     .build()?
//! #     .connect()
//! #     .await?;
//! let bulk_client = ClientBuilder::new(auth_client).build()?;
//!
//! // Create a query job
//! let job = bulk_client
//!     .query()
//!     .create_job(&CreateQueryJobRequest {
//!         operation: QueryOperation::Query,
//!         query: "SELECT Id, Name FROM Account LIMIT 10".to_string(),
//!         content_type: None,
//!         column_delimiter: None,
//!         line_ending: None,
//!     })
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Tooling API
//!
//! ```no_run
//! use salesforce_core::client::{self, Credentials};
//! use salesforce_core::toolingapi::{
//!     ClientBuilder, CreateManagedEventSubscriptionRequest,
//!     ManagedEventSubscriptionMetadata, ReplayPreset, SubscriptionState,
//! };
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let auth_client = client::Builder::new()
//! #     .credentials(Credentials {
//! #         client_id: "...".to_string(),
//! #         client_secret: Some("...".to_string()),
//! #         username: None,
//! #         password: None,
//! #         instance_url: "https://localhost".to_string(),
//! #         tenant_id: "...".to_string(),
//! #     })
//! #     .build()?
//! #     .connect()
//! #     .await?;
//! let tooling_client = ClientBuilder::new(auth_client).build()?;
//!
//! // Create managed event subscription
//! let subscription = CreateManagedEventSubscriptionRequest {
//!     full_name: "Managed_Sub_AccountChangeEvent".to_string(),
//!     metadata: ManagedEventSubscriptionMetadata {
//!         label: "Account Change Events".to_string(),
//!         topic_name: "/data/AccountChangeEvent".to_string(),
//!         default_replay: ReplayPreset::Latest,
//!         state: SubscriptionState::Run,
//!         error_recovery_replay: ReplayPreset::Latest,
//!     },
//! };
//! let response = tooling_client.create_managed_event_subscription(subscription).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Pub/Sub API
//!
//! ```no_run
//! use salesforce_core::client::{self, Credentials};
//! use salesforce_core::pubsubapi::{Client as PubSubClient, ManagedFetchRequest};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let auth_client = client::Builder::new()
//! #     .credentials(Credentials {
//! #         client_id: "...".to_string(),
//! #         client_secret: Some("...".to_string()),
//! #         username: None,
//! #         password: None,
//! #         instance_url: "https://localhost".to_string(),
//! #         tenant_id: "...".to_string(),
//! #     })
//! #     .build()?
//! #     .connect()
//! #     .await?;
//! let channel = tonic::transport::Channel::from_static(salesforce_core::pubsubapi::ENDPOINT)
//!     .connect()
//!     .await?;
//!
//! let mut pubsub_client = PubSubClient::new(channel, auth_client)?;
//!
//! let request = ManagedFetchRequest {
//!     developer_name: "Managed_Sub_AccountChangeEvent".to_string(),
//!     num_requested: 100,
//!     ..Default::default()
//! };
//!
//! let stream = pubsub_client.managed_subscribe(request).await?;
//! // Process events from stream...
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

/// Default TCP keepalive interval (60 seconds).
pub const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 60;

/// Default connection pool idle timeout (90 seconds).
pub const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 90;

/// Default maximum idle connections per host (10).
pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 10;

/// OAuth2 client authentication and connection management.
pub mod client;

/// Salesforce Pub/Sub API for real-time event streaming.
pub mod pubsubapi;

/// Salesforce Bulk API 2.0 for querying and ingesting large data sets.
pub mod bulkapi;

/// Salesforce REST API for SObject operations, queries, and searches.
pub mod restapi;

/// Salesforce Tooling API for metadata operations.
pub mod toolingapi;

/// Shared HTTP client utilities.
pub(crate) mod http;
