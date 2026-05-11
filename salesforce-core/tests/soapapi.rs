//! Integration tests for the SOAP API (merge operations).

mod common;

use salesforce_core::restapi::ClientBuilder as RestClientBuilder;
use salesforce_core::soapapi::ClientBuilder as SoapClientBuilder;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn test_merge_accounts() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let rest_client = RestClientBuilder::new(auth.clone()).build()?;
    let soap_client = SoapClientBuilder::new(auth).build()?;

    let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();

    let master = rest_client
        .create(
            "Account",
            json!({
                "Name": format!("Merge Master {suffix}"),
                "Industry": "Technology"
            }),
        )
        .await?;
    assert!(master.success);

    let duplicate = rest_client
        .create(
            "Account",
            json!({
                "Name": format!("Merge Duplicate {suffix}"),
                "BillingCity": "San Francisco"
            }),
        )
        .await?;
    assert!(duplicate.success);

    let mut master_fields = serde_json::Map::new();
    master_fields.insert("BillingCity".to_string(), json!("San Francisco"));

    let merge_result = soap_client
        .merge(
            "Account",
            &master.id,
            &[&duplicate.id],
            Some(&master_fields),
            true,
        )
        .await?;
    assert!(merge_result.success);

    let merged = rest_client
        .get("Account", &master.id, Some("Id,Name,BillingCity"))
        .await?;
    assert_eq!(
        merged.get("BillingCity").and_then(|v| v.as_str()),
        Some("San Francisco")
    );

    let duplicate_result = rest_client.get("Account", &duplicate.id, None).await;
    assert!(duplicate_result.is_err());

    rest_client.delete("Account", &master.id).await?;

    Ok(())
}
