//! Salesforce REST API.
//!
//! This module provides access to Salesforce REST API resources.
//!
//! ## Currently Supported Operations
//!
//! - SObject CRUD operations (create, read, update, delete, describe)
//!
//! # Examples
//!
//! ```no_run
//! use salesforce_core::client::{self, Credentials};
//! use salesforce_core::restapi;
//! use serde_json::json;
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
//!
//! let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
//!
//! // Create a record
//! let data = json!({
//!     "Name": "Acme Corporation",
//!     "Industry": "Technology"
//! });
//! let response = rest_client.create("Account", data).await?;
//! let record_id = response.id;
//! # Ok(())
//! # }
//! ```

/// REST API client and builder.
mod client;

/// SObject CRUD operations for individual records.
pub mod sobject;

/// Composite API operations for bulk record operations.
pub mod composite;

pub use client::{Client, ClientBuilder, Error as ClientError};

// SObject types
pub use salesforce_core_restapi::types::{CreateRecordResponse, SObjectDescribe, SObjectField};
pub use sobject::Error as SObjectError;

// Composite types
pub use composite::Error as CompositeError;
pub use salesforce_core_restapi::types::{
    CompositeCollectionCreateRequest, CompositeCollectionCreateResponse,
    CompositeCollectionDeleteResponse, CompositeCollectionRetrieveRequest,
    CompositeCollectionUpdateRequest, CompositeCollectionUpdateResponse,
    CompositeCollectionUpsertRequest, CompositeCollectionUpsertResponse, CompositeRecordRequest,
    CompositeRecordResult, CompositeTreeRecord, CompositeTreeRequest, CompositeTreeResponse,
    CompositeTreeResult,
};
