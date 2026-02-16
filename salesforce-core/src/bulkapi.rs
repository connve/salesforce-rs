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
//! use salesforce_core::bulkapi::ClientBuilder;
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
//! // Create Bulk API client with default API version (v65.0)
//! let bulk_client = ClientBuilder::new(auth_client.clone()).build();
//!
//! // Or specify a custom API version
//! let bulk_client_custom = ClientBuilder::new(auth_client)
//!     .api_version("64.0")
//!     .build();
//!
//! // Use query and ingest operations
//! let query_client = bulk_client.query();
//! let ingest_client = bulk_client.ingest();
//! # Ok(())
//! # }
//! ```

mod client;
pub mod ingest;
pub mod query;

pub use client::{Client, ClientBuilder};

/// Re-export error types from query and ingest modules.
pub use ingest::Error as IngestError;
pub use query::Error as QueryError;

/// Re-export commonly used types from the generated client.
pub use salesforce_core_v1::types::{
    // Enums
    ColumnDelimiter,
    ConcurrencyMode,
    ContentType,
    // Ingest types
    CreateIngestJobRequest,
    // Query types
    CreateQueryJobRequest,
    GetAllIngestJobsResponse,
    IngestJobInfo,
    IngestOperation,
    JobState,
    JobType,
    LineEnding,
    QueryJobInfo,
    QueryJobList,
    QueryOperation,
    QueryResultPages,
};

/// Re-export ByteStream for handling streaming results.
pub use salesforce_core_v1::ByteStream;
