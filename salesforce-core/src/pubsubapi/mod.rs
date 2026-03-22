//! Salesforce Pub/Sub API for real-time event streaming.
//!
//! This module provides access to the Salesforce Pub/Sub API, which allows you to:
//! - Subscribe to platform events and change data capture events
//! - Publish custom platform events
//! - Manage gRPC connections with automatic authentication
//!
//! # Example
//!
//! ```no_run
//! use salesforce_core::client;
//! use salesforce_core::pubsubapi::Client as PubSubClient;
//! use salesforce_core_pubsubapi::eventbus;
//! use std::path::PathBuf;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let auth_client = client::Builder::new()
//!     .credentials_path(PathBuf::from("credentials.json"))
//!     .build()?
//!     .connect()
//!     .await?;
//!
//! let channel = tonic::transport::Channel::from_static(eventbus::ENDPOINT)
//!     .connect()
//!     .await?;
//!
//! let mut pubsub_client = PubSubClient::new(channel, auth_client)?;
//! # Ok(())
//! # }
//! ```

mod client;

pub use client::Client;
pub use client::Error as PubSubError;

/// Re-export commonly used types from the generated gRPC client.
pub use salesforce_core_pubsubapi::eventbus::{self, v1::*};

/// Constant for the Pub/Sub API endpoint.
pub use salesforce_core_pubsubapi::eventbus::ENDPOINT;
