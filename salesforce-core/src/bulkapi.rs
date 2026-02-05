//! Salesforce Bulk API v2.0 for querying and ingesting large data sets.
//!
//! This module provides access to the Salesforce Bulk API v2.0, which allows you to:
//! - **Query**: Asynchronously query large data sets using SOQL
//! - **Ingest**: Load, update, upsert, or delete large numbers of records
//!
//! # Example
//!
//! ```no_run
//! use salesforce_core::client::{self, Credentials};
//! use salesforce_core::bulkapi::Client as BulkClient;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create and connect auth client
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
//!
//! // Create Bulk API client
//! let bulk_client = BulkClient::new(auth_client, salesforce_core::DEFAULT_API_VERSION);
//!
//! // Use query and ingest operations
//! let query_client = bulk_client.query();
//! let ingest_client = bulk_client.ingest();
//! # Ok(())
//! # }
//! ```

mod client;
pub mod query;
pub mod ingest;

pub use client::Client;

/// Re-export commonly used types from the generated client.
pub use salesforce_core_v1::types::{
    // Enums
    ColumnDelimiter,
    ConcurrencyMode,
    ContentType,
    IngestOperation,
    JobState,
    JobType,
    LineEnding,
    QueryOperation,
    // Query types
    CreateQueryJobRequest,
    QueryJobInfo,
    QueryJobList,
    QueryResultPages,
    // Ingest types
    CreateIngestJobRequest,
    GetAllIngestJobsResponse,
    IngestJobInfo,
};

/// Re-export ByteStream for handling streaming results.
pub use salesforce_core_v1::ByteStream;
