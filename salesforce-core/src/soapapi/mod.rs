//! Salesforce SOAP API.
//!
//! This module provides access to Salesforce operations that are only
//! available through the SOAP API, such as record merging.
//!
//! ## Currently Supported Operations
//!
//! - Record merge (Account, Contact, Lead, Individual)
//!
//! # Example
//!
//! ```no_run
//! use salesforce_core::client;
//! use salesforce_core::soapapi;
//! use serde_json::json;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let auth_client = client::Client::builder()
//!     .client_id("...")
//!     .client_secret("...")
//!     .instance_url("https://your-instance.my.salesforce.com")
//!     .build()?
//!     .connect()
//!     .await?;
//!
//! let soap_client = soapapi::ClientBuilder::new(auth_client).build()?;
//!
//! let mut overrides = serde_json::Map::new();
//! overrides.insert("BillingCity".to_string(), json!("San Francisco"));
//!
//! let result = soap_client
//!     .merge("Account", "001xx000003DGb2AAG", &["001xx000003DGb3AAG"], Some(&overrides), true)
//!     .await?;
//! # Ok(())
//! # }
//! ```

/// SOAP API client and builder.
mod client;

/// Record merge operations.
pub mod merge;

pub use client::{Client, ClientBuilder, Error as ClientError};
pub use merge::{Error as MergeError, MergeResponse};
