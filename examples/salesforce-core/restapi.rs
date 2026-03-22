//! Example of using the REST API for SObject CRUD operations.
//!
//! This example demonstrates:
//! - Creating records
//! - Reading records by ID
//! - Reading records by external ID
//! - Updating records
//! - Deleting records
//! - Describing SObject metadata

use salesforce_core::client::{self, Credentials};
use salesforce_core::restapi::ClientBuilder;
use serde_json::json;
use std::env;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt::init();

    // Initialize the Salesforce authentication client
    let auth_client = client::Builder::new()
        .credentials(Credentials {
            client_id: env::var("SALESFORCE_CLIENT_ID")?,
            client_secret: Some(env::var("SALESFORCE_CLIENT_SECRET")?),
            username: None,
            password: None,
            instance_url: env::var("SALESFORCE_INSTANCE_URL")?,
            tenant_id: env::var("SALESFORCE_TENANT_ID")?,
        })
        .build()?
        .connect()
        .await?;

    // Create REST API client
    let rest_client = ClientBuilder::new(auth_client).build();

    info!("REST API client initialized successfully");

    // Example 1: Create a new Account record
    info!("\n--- Example 1: Creating a new Account ---");
    let account_data = json!({
        "Name": "Acme Corporation",
        "Industry": "Technology",
        "BillingCity": "San Francisco",
        "BillingState": "CA",
        "NumberOfEmployees": 500
    });

    let account_id = rest_client.create("Account", account_data).await?;
    info!("Created Account with ID: {}", account_id);

    // Example 2: Read the created record
    info!("\n--- Example 2: Reading Account by ID ---");
    let account = rest_client
        .get("Account", &account_id, Some("Id,Name,Industry,BillingCity"))
        .await?;
    info!(
        "Retrieved Account: {}",
        serde_json::to_string_pretty(&account)?
    );

    // Example 3: Update the record
    info!("\n--- Example 3: Updating Account ---");
    let update_data = json!({
        "Industry": "Software",
        "NumberOfEmployees": 750,
        "Description": "Updated via REST API example"
    });

    rest_client
        .update("Account", &account_id, update_data)
        .await?;
    info!("Account updated successfully");

    // Read the updated record to verify
    let updated_account = rest_client
        .get(
            "Account",
            &account_id,
            Some("Id,Name,Industry,NumberOfEmployees,Description"),
        )
        .await?;
    info!(
        "Updated Account: {}",
        serde_json::to_string_pretty(&updated_account)?
    );

    // Example 4: Describe SObject metadata
    info!("\n--- Example 4: Describing Account SObject ---");
    let describe = rest_client.describe("Account").await?;
    info!("Account metadata:");
    info!("  - Name: {}", describe.name);
    info!("  - Label: {}", describe.label);
    info!("  - Createable: {}", describe.createable);
    info!("  - Updateable: {}", describe.updateable);
    info!("  - Deletable: {}", describe.deletable);
    info!("  - Number of fields: {}", describe.fields.len());

    // Show first 5 fields as example
    info!("  - First 5 fields:");
    for field in describe.fields.iter().take(5) {
        info!("    - {} ({}): {}", field.name, field.type_, field.label);
    }

    // Example 5: Create a Contact record
    info!("\n--- Example 5: Creating a Contact ---");
    let contact_data = json!({
        "FirstName": "Jane",
        "LastName": "Doe",
        "Email": "jane.doe@example.com",
        "AccountId": account_id,
        "Title": "VP of Engineering"
    });

    let contact_id = rest_client.create("Contact", contact_data).await?;
    info!("Created Contact with ID: {}", contact_id);

    // Example 6: Query using external ID (if you have one configured)
    // Uncomment and modify if you have external ID fields configured
    /*
    info!("\n--- Example 6: Reading by External ID ---");
    let external_record = rest_client
        .get_by_external_id(
            "Account",
            "ExternalId__c",
            "EXT-12345",
            Some("Id,Name,ExternalId__c")
        )
        .await?;
    info!("Retrieved by external ID: {}", serde_json::to_string_pretty(&external_record)?);
    */

    // Example 7: Clean up - Delete the created records
    info!("\n--- Example 7: Cleaning up ---");

    // Delete Contact first (has relationship to Account)
    rest_client.delete("Contact", &contact_id).await?;
    info!("Deleted Contact: {}", contact_id);

    // Delete Account
    rest_client.delete("Account", &account_id).await?;
    info!("Deleted Account: {}", account_id);

    info!("\n✓ All REST API examples completed successfully!");

    Ok(())
}
