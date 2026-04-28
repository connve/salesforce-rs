//! Example of using the Tooling API to create Managed Event Subscriptions.
//!
//! This example demonstrates:
//! - Creating a ManagedEventSubscription for Change Data Capture events
//! - Configuring replay behavior and error recovery
//! - Using the subscription with Pub/Sub API's managed_subscribe() method
//!
//! Note: This example creates a ManagedEventSubscription metadata record.
//! After creation, you can use it with the Pub/Sub API's managed_subscribe()
//! method as shown in the pubsubapi.rs example.

use salesforce_core::client;
use salesforce_core::toolingapi::{
    ClientBuilder, CreateManagedEventSubscriptionRequest, ManagedEventSubscriptionMetadata,
    ReplayPreset, SubscriptionState,
};
use std::env;
use std::path::PathBuf;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let credentials_path = PathBuf::from(env::var("SFDC_CREDENTIALS")?);
    let auth_client = client::Builder::new()
        .credentials_path(credentials_path)
        .build()?
        .connect()
        .await?;

    // Create Tooling API client with default API version (v65.0)
    let tooling_client = ClientBuilder::new(auth_client.clone()).build()?;

    info!("Tooling API client initialized successfully");

    // Example 1: Create a managed event subscription for Account Change Events
    info!("\n--- Example 1: Creating ManagedEventSubscription for Account ---");

    let account_subscription = CreateManagedEventSubscriptionRequest {
        full_name: "Managed_Sub_AccountChangeEvent".to_string(),
        metadata: ManagedEventSubscriptionMetadata {
            label: "Managed Subscription for Account Change Events".to_string(),
            topic_name: "/data/AccountChangeEvent".to_string(),
            default_replay: ReplayPreset::Latest,
            state: SubscriptionState::Run,
            error_recovery_replay: ReplayPreset::Latest,
        },
    };

    match tooling_client
        .create_managed_event_subscription(account_subscription)
        .await
    {
        Ok(response) => {
            info!("✓ Successfully created ManagedEventSubscription!");
            info!("  - ID: {}", response.id);
            info!("  - Success: {}", response.success);
            if !response.errors.is_empty() {
                info!("  - Errors: {:?}", response.errors);
            }
        }
        Err(e) => {
            info!("Failed to create AccountChangeEvent subscription: {}", e);
            info!("This may be expected if the subscription already exists.");
        }
    }

    // Example 2: Create a managed event subscription for Opportunity Change Events
    info!("\n--- Example 2: Creating ManagedEventSubscription for Opportunity ---");

    let opportunity_subscription = CreateManagedEventSubscriptionRequest {
        full_name: "Managed_Sub_OpportunityChangeEvent".to_string(),
        metadata: ManagedEventSubscriptionMetadata {
            label: "Managed Subscription for Opportunity Change Events".to_string(),
            topic_name: "/data/OpportunityChangeEvent".to_string(),
            default_replay: ReplayPreset::Earliest, // Start from earliest available event
            state: SubscriptionState::Run,
            error_recovery_replay: ReplayPreset::Latest, // On error, resume from latest
        },
    };

    match tooling_client
        .create_managed_event_subscription(opportunity_subscription)
        .await
    {
        Ok(response) => {
            info!("✓ Successfully created ManagedEventSubscription!");
            info!("  - ID: {}", response.id);
            info!("  - Success: {}", response.success);
            if !response.errors.is_empty() {
                info!("  - Errors: {:?}", response.errors);
            }
        }
        Err(e) => {
            info!(
                "Failed to create OpportunityChangeEvent subscription: {}",
                e
            );
            info!("This may be expected if the subscription already exists.");
        }
    }

    // Example 3: Create a subscription in STOP state (paused)
    info!("\n--- Example 3: Creating ManagedEventSubscription in STOP state ---");

    let paused_subscription = CreateManagedEventSubscriptionRequest {
        full_name: "Managed_Sub_ContactChangeEvent".to_string(),
        metadata: ManagedEventSubscriptionMetadata {
            label: "Paused Subscription for Contact Change Events".to_string(),
            topic_name: "/data/ContactChangeEvent".to_string(),
            default_replay: ReplayPreset::Latest,
            state: SubscriptionState::Stop, // Created in paused state
            error_recovery_replay: ReplayPreset::Latest,
        },
    };

    match tooling_client
        .create_managed_event_subscription(paused_subscription)
        .await
    {
        Ok(response) => {
            info!("✓ Successfully created ManagedEventSubscription (paused)!");
            info!("  - ID: {}", response.id);
            info!("  - Success: {}", response.success);
            info!("  - Note: This subscription is in STOP state and won't receive events");
            info!("           until updated to RUN state via Salesforce UI or Metadata API");
            if !response.errors.is_empty() {
                info!("  - Errors: {:?}", response.errors);
            }
        }
        Err(e) => {
            info!("Failed to create ContactChangeEvent subscription: {}", e);
            info!("This may be expected if the subscription already exists.");
        }
    }

    info!("\n--- Usage Instructions ---");
    info!("To use these subscriptions with the Pub/Sub API:");
    info!("1. Use the 'managed_subscribe()' method in the Pub/Sub API client");
    info!("2. Provide the developer_name (e.g., 'Managed_Sub_AccountChangeEvent')");
    info!("3. The subscription will use the replay settings configured here");
    info!("");
    info!("Example code:");
    info!("  let request = ManagedFetchRequest {{");
    info!("      developer_name: \"Managed_Sub_AccountChangeEvent\".to_string(),");
    info!("      num_requested: 100,");
    info!("      ..Default::default()");
    info!("  }};");
    info!("  let stream = pubsub_client.managed_subscribe(request).await?;");

    info!("\n--- Replay Preset Information ---");
    info!("LATEST:  Subscribe to new events from now onwards");
    info!("EARLIEST: Subscribe to all retained events from the beginning");
    info!("");
    info!("Error Recovery Replay determines where to resume after an error.");

    info!("\n✓ Tooling API examples completed successfully!");
    info!("\nNote: To clean up, delete these subscriptions via Salesforce Setup UI:");
    info!("  Setup → Platform Events → Event Manager → Subscriptions");

    Ok(())
}
