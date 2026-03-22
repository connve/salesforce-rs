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

use serde::{Deserialize, Serialize};

pub use client::{Client, ClientBuilder, Error};

/// Replay preset for managed event subscriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ReplayPreset {
    /// Start from the latest event.
    Latest,
    /// Start from the earliest retained event.
    Earliest,
}

/// State of a managed event subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SubscriptionState {
    /// Subscription is actively running.
    Run,
    /// Subscription is stopped.
    Stop,
}

/// Metadata for a managed event subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedEventSubscriptionMetadata {
    /// Human-readable label for the subscription.
    pub label: String,

    /// Topic name to subscribe to (e.g., "/data/OpportunityChangeEvent").
    pub topic_name: String,

    /// Default replay preset for the subscription.
    pub default_replay: ReplayPreset,

    /// Current state of the subscription.
    pub state: SubscriptionState,

    /// Replay preset to use for error recovery.
    pub error_recovery_replay: ReplayPreset,
}

/// Request to create a managed event subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateManagedEventSubscriptionRequest {
    /// Full API name of the managed event subscription.
    pub full_name: String,

    /// Metadata configuration for the subscription.
    pub metadata: ManagedEventSubscriptionMetadata,
}

/// Response from creating a managed event subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateManagedEventSubscriptionResponse {
    /// Salesforce ID of the created subscription.
    pub id: String,

    /// Whether the operation succeeded.
    pub success: bool,

    /// List of errors (empty on success).
    #[serde(default)]
    pub errors: Vec<ToolingApiError>,
}

/// Error detail from Salesforce Tooling API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolingApiError {
    /// Error code identifier.
    pub status_code: String,

    /// Descriptive error message.
    pub message: String,

    /// Fields that caused the error.
    #[serde(default)]
    pub fields: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_preset_serialization() {
        // Verify ReplayPreset serializes to UPPERCASE as required by Salesforce API.
        let latest = ReplayPreset::Latest;
        let earliest = ReplayPreset::Earliest;

        assert_eq!(serde_json::to_string(&latest).unwrap(), r#""LATEST""#);
        assert_eq!(serde_json::to_string(&earliest).unwrap(), r#""EARLIEST""#);
    }

    #[test]
    fn test_replay_preset_deserialization() {
        // Verify ReplayPreset deserializes from UPPERCASE.
        let latest: ReplayPreset = serde_json::from_str(r#""LATEST""#).unwrap();
        let earliest: ReplayPreset = serde_json::from_str(r#""EARLIEST""#).unwrap();

        assert_eq!(latest, ReplayPreset::Latest);
        assert_eq!(earliest, ReplayPreset::Earliest);
    }

    #[test]
    fn test_subscription_state_serialization() {
        // Verify SubscriptionState serializes to UPPERCASE as required by Salesforce API.
        let run = SubscriptionState::Run;
        let stop = SubscriptionState::Stop;

        assert_eq!(serde_json::to_string(&run).unwrap(), r#""RUN""#);
        assert_eq!(serde_json::to_string(&stop).unwrap(), r#""STOP""#);
    }

    #[test]
    fn test_subscription_state_deserialization() {
        // Verify SubscriptionState deserializes from UPPERCASE.
        let run: SubscriptionState = serde_json::from_str(r#""RUN""#).unwrap();
        let stop: SubscriptionState = serde_json::from_str(r#""STOP""#).unwrap();

        assert_eq!(run, SubscriptionState::Run);
        assert_eq!(stop, SubscriptionState::Stop);
    }

    #[test]
    fn test_managed_event_subscription_metadata_serialization() {
        // Verify ManagedEventSubscriptionMetadata uses camelCase for field names.
        let metadata = ManagedEventSubscriptionMetadata {
            label: "Test Subscription".to_string(),
            topic_name: "/data/OpportunityChangeEvent".to_string(),
            default_replay: ReplayPreset::Latest,
            state: SubscriptionState::Run,
            error_recovery_replay: ReplayPreset::Earliest,
        };

        let json = serde_json::to_value(&metadata).unwrap();

        // Verify camelCase field names as required by Salesforce API.
        assert_eq!(json["label"], "Test Subscription");
        assert_eq!(json["topicName"], "/data/OpportunityChangeEvent");
        assert_eq!(json["defaultReplay"], "LATEST");
        assert_eq!(json["state"], "RUN");
        assert_eq!(json["errorRecoveryReplay"], "EARLIEST");
    }

    #[test]
    fn test_create_managed_event_subscription_request_serialization() {
        // Verify CreateManagedEventSubscriptionRequest uses PascalCase for top-level fields.
        let request = CreateManagedEventSubscriptionRequest {
            full_name: "Managed_Sub_Test".to_string(),
            metadata: ManagedEventSubscriptionMetadata {
                label: "Test".to_string(),
                topic_name: "/data/Test".to_string(),
                default_replay: ReplayPreset::Latest,
                state: SubscriptionState::Run,
                error_recovery_replay: ReplayPreset::Latest,
            },
        };

        let json = serde_json::to_value(&request).unwrap();

        // Verify PascalCase field names as required by Salesforce Tooling API.
        assert_eq!(json["FullName"], "Managed_Sub_Test");
        assert!(json["Metadata"].is_object());
        assert_eq!(json["Metadata"]["label"], "Test");
    }

    #[test]
    fn test_create_managed_event_subscription_response_success() {
        // Test successful response deserialization.
        let json = r#"{
            "id": "0Xaxx000000001AAA",
            "success": true,
            "errors": []
        }"#;

        let response: CreateManagedEventSubscriptionResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.id, "0Xaxx000000001AAA");
        assert!(response.success);
        assert!(response.errors.is_empty());
    }

    #[test]
    fn test_create_managed_event_subscription_response_error() {
        // Test error response deserialization with proper field name mapping.
        let json = r#"{
            "id": "",
            "success": false,
            "errors": [
                {
                    "statusCode": "INVALID_FIELD",
                    "message": "Invalid topic name",
                    "fields": ["topicName"]
                }
            ]
        }"#;

        let response: CreateManagedEventSubscriptionResponse = serde_json::from_str(json).unwrap();

        assert!(!response.success);
        assert_eq!(response.errors.len(), 1);
        assert_eq!(response.errors[0].status_code, "INVALID_FIELD");
        assert_eq!(response.errors[0].message, "Invalid topic name");
        assert_eq!(response.errors[0].fields, vec!["topicName"]);
    }

    #[test]
    fn test_tooling_api_error_camel_case_fields() {
        // Verify ToolingApiError uses camelCase for field names.
        let json = r#"{
            "statusCode": "DUPLICATE_VALUE",
            "message": "Duplicate subscription name",
            "fields": ["fullName"]
        }"#;

        let error: ToolingApiError = serde_json::from_str(json).unwrap();

        assert_eq!(error.status_code, "DUPLICATE_VALUE");
        assert_eq!(error.message, "Duplicate subscription name");
        assert_eq!(error.fields, vec!["fullName"]);
    }

    #[test]
    fn test_tooling_api_error_default_fields() {
        // Verify fields defaults to empty vec when not provided.
        let json = r#"{
            "statusCode": "UNKNOWN_ERROR",
            "message": "Something went wrong"
        }"#;

        let error: ToolingApiError = serde_json::from_str(json).unwrap();

        assert_eq!(error.status_code, "UNKNOWN_ERROR");
        assert_eq!(error.message, "Something went wrong");
        assert!(error.fields.is_empty());
    }
}
