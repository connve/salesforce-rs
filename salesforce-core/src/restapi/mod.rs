//! Salesforce REST API.
//!
//! This module provides access to Salesforce REST API resources.
//!
//! ## Currently Supported Operations
//!
//! - SObject CRUD operations (create, read, update, delete, describe, get deleted)
//! - SOQL queries, including `queryAll` and pagination via `nextRecordsUrl`
//! - SOSL search
//! - Flow invocation via Custom Invocable Actions
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
//!         client_secret: Some("...".into()),
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
//! // Create a record:
//! let data = json!({
//!     "Name": "Acme Corporation",
//!     "Industry": "Technology"
//! });
//! let response = rest_client.create("Account", data).send().await?;
//! let record_id = response.id;
//!
//! // Or attach a Salesforce request header (e.g. duplicate-rule override):
//! let _ = rest_client
//!     .create("Account", json!({ "Name": "Acme" }))
//!     .header("Sforce-Duplicate-Rule-Header", "allowSave=true")
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```

/// REST API client and builder.
mod client;

/// Per-call request header plumbing shared by the request builders.
mod headers;

/// SObject CRUD operations for individual records.
pub mod sobject;

/// Composite API operations for bulk record operations.
pub mod composite;

/// SOQL query operations.
pub mod query;

/// SOSL search operations.
pub mod search;

/// Flow invocation via Custom Invocable Actions.
pub mod flow;

pub use client::{Client, ClientBuilder, Error as ClientError};

// SObject types
pub use salesforce_core_restapi::types::{
    CreateRecordResponse, DeletedRecord, GetDeletedRecordsResponse, SObjectDescribe, SObjectField,
};
pub use sobject::Error as SObjectError;

// Query types
pub use query::Error as QueryError;
pub use salesforce_core_restapi::types::QueryResponse;

// Search types
pub use salesforce_core_restapi::types::{SearchRecord, SearchRecordAttributes, SearchResponse};
pub use search::Error as SearchError;

// Flow types
pub use flow::Error as FlowError;
pub use salesforce_core_restapi::types::{FlowInvokeRequest, FlowInvokeResponse, FlowInvokeResult};

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
