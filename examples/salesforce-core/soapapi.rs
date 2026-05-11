//! Example of using the SOAP API for merge operations.
//!
//! This example demonstrates merging two Account records into one,
//! preserving a field value from the losing record.

use salesforce_core::client;
use salesforce_core::restapi::ClientBuilder as RestClientBuilder;
use salesforce_core::soapapi::ClientBuilder as SoapClientBuilder;
use serde_json::json;
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

    // Create both REST and SOAP clients from the same auth client.
    let rest_client = RestClientBuilder::new(auth_client.clone()).build()?;
    let soap_client = SoapClientBuilder::new(auth_client).build()?;

    info!("Clients initialized successfully");

    // Create two accounts to merge.
    info!("\n--- Creating accounts ---");
    let master = rest_client
        .create(
            "Account",
            json!({
                "Name": "Acme Corporation",
                "Industry": "Technology"
            }),
        )
        .await?;
    info!("Created master Account: {}", master.id);

    let duplicate = rest_client
        .create(
            "Account",
            json!({
                "Name": "Acme Corp (Duplicate)",
                "BillingCity": "San Francisco"
            }),
        )
        .await?;
    info!("Created duplicate Account: {}", duplicate.id);

    // Merge the duplicate into the master, keeping the BillingCity value.
    info!("\n--- Merging accounts ---");
    let mut overrides = serde_json::Map::new();
    overrides.insert("BillingCity".to_string(), json!("San Francisco"));

    let result = soap_client
        .merge(
            "Account",
            &master.id,
            &[&duplicate.id],
            Some(&overrides),
            true,
        )
        .await?;
    info!("Merge successful: {}", result.success);
    info!("Merged record IDs: {:?}", result.merged_record_ids);
    info!("Updated related IDs: {:?}", result.updated_related_ids);

    // Verify the merge result.
    let merged = rest_client
        .get("Account", &master.id, Some("Id,Name,BillingCity"))
        .await?;
    info!("Merged Account: {}", serde_json::to_string_pretty(&merged)?);

    // Clean up.
    info!("\n--- Cleaning up ---");
    rest_client.delete("Account", &master.id).await?;
    info!("Deleted Account: {}", master.id);

    Ok(())
}
