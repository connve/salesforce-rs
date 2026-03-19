use salesforce_core::client::{self, AuthFlow, Credentials};
use salesforce_core::pubsub::{Client as PubSubClient, ManagedFetchRequest, ENDPOINT};
use salesforce_core::tooling::{
    self, CreateManagedEventSubscriptionRequest, ManagedEventSubscriptionMetadata, ReplayPreset,
    SubscriptionState,
};
use std::env;
use tokio_stream::StreamExt;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber for logging.
    tracing_subscriber::fmt::init();

    // Step 1: Initialize and authenticate the Salesforce client.
    info!("Authenticating with Salesforce...");
    let auth_client = client::Builder::new()
        .credentials(Credentials {
            client_id: env::var("SALESFORCE_CLIENT_ID")
                .expect("SALESFORCE_CLIENT_ID environment variable not set"),
            client_secret: Some(
                env::var("SALESFORCE_CLIENT_SECRET")
                    .expect("SALESFORCE_CLIENT_SECRET environment variable not set"),
            ),
            username: Some(
                env::var("SALESFORCE_USERNAME")
                    .expect("SALESFORCE_USERNAME environment variable not set"),
            ),
            password: Some(
                env::var("SALESFORCE_PASSWORD")
                    .expect("SALESFORCE_PASSWORD environment variable not set"),
            ),
            instance_url: env::var("SALESFORCE_INSTANCE_URL")
                .unwrap_or_else(|_| "https://login.salesforce.com".to_string()),
            tenant_id: env::var("SALESFORCE_TENANT_ID")
                .expect("SALESFORCE_TENANT_ID environment variable not set"),
        })
        .auth_flow(AuthFlow::UsernamePassword)
        .build()?
        .connect()
        .await?;

    info!("Successfully authenticated");

    // Step 2: Create a Tooling API client to create the managed subscription.
    let tooling_client = tooling::ClientBuilder::new(auth_client.clone()).build();

    // Step 3: Define the managed event subscription configuration.
    //
    // This creates a subscription to OpportunityChangeEvent that:
    // - Starts from the latest event (LATEST replay)
    // - Runs immediately (RUN state)
    // - Uses LATEST replay for error recovery
    let subscription_request = CreateManagedEventSubscriptionRequest {
        full_name: "Managed_Sub_OpportunityChangeEvent".to_string(),
        metadata: ManagedEventSubscriptionMetadata {
            label: "Managed Sub OpportunityChangeEvent".to_string(),
            topic_name: "/data/OpportunityChangeEvent".to_string(),
            default_replay: ReplayPreset::Latest,
            state: SubscriptionState::Run,
            error_recovery_replay: ReplayPreset::Latest,
        },
    };

    // Step 4: Create the managed event subscription via Tooling API.
    info!("Creating managed event subscription...");
    let create_response = tooling_client
        .create_managed_event_subscription(subscription_request)
        .await?;

    if create_response.success {
        info!(
            "Successfully created managed subscription with ID: {}",
            create_response.id
        );
    } else {
        error!("Failed to create subscription: {:?}", create_response.errors);
        return Err("Subscription creation failed".into());
    }

    // Step 5: Connect to the Pub/Sub API to consume events.
    info!("Connecting to Pub/Sub API...");
    let channel = tonic::transport::Channel::from_static(ENDPOINT)
        .connect()
        .await?;

    let mut pubsub_client = PubSubClient::new(channel, auth_client)?;
    info!("Connected to Pub/Sub API");

    // Step 6: Subscribe to events using the managed subscription.
    //
    // The subscription_id can be either:
    // - The Salesforce ID returned from the Tooling API (e.g., "0Xaxx000000001AAA")
    // - The developer name (e.g., "Managed_Sub_OpportunityChangeEvent")
    //
    // We use the developer name for clarity.
    let managed_fetch_request = ManagedFetchRequest {
        subscription_id: String::new(), // Can use ID or developer_name
        developer_name: "Managed_Sub_OpportunityChangeEvent".to_string(),
        num_requested: 100, // Request up to 100 events at a time
        ..Default::default()
    };

    info!("Subscribing to managed subscription...");
    match pubsub_client.managed_subscribe(managed_fetch_request).await {
        Ok(response) => {
            info!("Successfully subscribed to managed subscription");
            let mut stream = response.into_inner();

            // Step 7: Process events from the stream.
            //
            // The managed subscription handles:
            // - Automatic replay ID tracking
            // - Error recovery using the configured replay preset
            // - Durable subscription state in Salesforce
            info!("Listening for OpportunityChangeEvent events...");
            while let Some(result) = stream.next().await {
                match result {
                    Ok(managed_fetch_response) => {
                        info!(
                            "Received {} events from managed subscription",
                            managed_fetch_response.events.len()
                        );

                        for event in &managed_fetch_response.events {
                            info!("Event replay_id: {:?}", event.replay_id);

                            // Decode the Avro event payload.
                            // The event.event field contains the serialized Avro data
                            // that you can decode using the schema from the event.
                            //
                            // Example (requires avro-rs crate):
                            // let schema = apache_avro::Schema::parse_str(&schema_json)?;
                            // let value = apache_avro::from_avro_datum(&schema, &event.event, None)?;
                            // info!("Event data: {:?}", value);
                        }

                        // The managed subscription automatically commits replay IDs,
                        // so you don't need to manually send commit requests.
                        // If you need custom commit logic, you can use:
                        // managed_fetch_request.commit_replay_id = Some(replay_id);
                    }
                    Err(e) => {
                        error!("Stream error: {}", e);

                        // With managed subscriptions, the Pub/Sub API automatically
                        // handles error recovery using the error_recovery_replay setting.
                        // The subscription will resume from the appropriate replay ID.
                        break;
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to subscribe to managed subscription: {}", e);
            return Err(e.into());
        }
    }

    info!("Managed subscription example completed");
    Ok(())
}
