//! Salesforce SObject REST API for CRUD operations on individual records.
//!
//! This module provides a high-level interface for creating, reading, updating,
//! and deleting Salesforce records using the REST API.
//!
//! # Examples
//!
//! ```no_run
//! use salesforce_core::client::{self, Credentials};
//! use salesforce_core::sobject;
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
//! let sobject_client = sobject::ClientBuilder::new(auth_client).build();
//!
//! // Create a record
//! let account_data = json!({
//!     "Name": "Acme Corporation",
//!     "Industry": "Technology"
//! });
//! let record_id = sobject_client.create("Account", account_data).await?;
//!
//! // Read a record
//! let record = sobject_client.get("Account", &record_id, None).await?;
//!
//! // Update a record
//! let update_data = json!({
//!     "Industry": "Manufacturing"
//! });
//! sobject_client.update("Account", &record_id, update_data).await?;
//!
//! // Delete a record
//! sobject_client.delete("Account", &record_id).await?;
//! # Ok(())
//! # }
//! ```

mod client;
mod crud;

pub use client::{Client, ClientBuilder};
pub use crud::Error;
