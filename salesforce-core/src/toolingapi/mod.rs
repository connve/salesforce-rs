//! Salesforce Tooling API for metadata operations.
//!
//! This module provides access to the Salesforce Tooling API.
//!
//! ## Currently Supported Operations
//!
//! - Create ManagedEventSubscription records via POST endpoint
//!
//! # Examples
//!
//! ```no_run
//! use salesforce_core::client::{self, Credentials};
//! use salesforce_core::toolingapi::{self, ManagedEventSubscriptionMetadata, ReplayPreset};
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
//! let tooling_client = toolingapi::ClientBuilder::new(auth_client).build()?;
//!
//! // Create a managed event subscription
//! let subscription = toolingapi::CreateManagedEventSubscriptionRequest {
//!     full_name: "Managed_Sub_OpportunityChangeEvent".to_string(),
//!     metadata: ManagedEventSubscriptionMetadata {
//!         label: "Managed Sub OpportunityChangeEvent".to_string(),
//!         topic_name: "/data/OpportunityChangeEvent".to_string(),
//!         default_replay: ReplayPreset::Latest,
//!         state: toolingapi::SubscriptionState::Run,
//!         error_recovery_replay: ReplayPreset::Latest,
//!     },
//! };
//!
//! let response = tooling_client.create_managed_event_subscription(subscription).await?;
//! println!("Created subscription with ID: {}", response.id);
//! # Ok(())
//! # }
//! ```

mod client;
mod error;
mod types;

pub use client::{Client, ClientBuilder};
pub use error::Error;
pub use types::{
    CreateManagedEventSubscriptionRequest, CreateManagedEventSubscriptionResponse,
    ManagedEventSubscriptionMetadata, ReplayPreset, SubscriptionState,
};
