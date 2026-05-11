//! Integration tests for the SOAP API (merge operations).

mod common;

use salesforce_core::restapi::ClientBuilder as RestClientBuilder;
use salesforce_core::soapapi::ClientBuilder as SoapClientBuilder;
use serde_json::json;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn test_merge_accounts() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let rest_client = RestClientBuilder::new(auth.clone()).build()?;
    let soap_client = SoapClientBuilder::new(auth).build()?;

    let master = rest_client
        .create(
            "Account",
            json!({
                "Name": "Merge Master Account",
                "Industry": "Technology"
            }),
        )
        .await?;
    assert!(master.success);

    let loser = rest_client
        .create(
            "Account",
            json!({
                "Name": "Merge Loser Account",
                "BillingCity": "San Francisco"
            }),
        )
        .await?;
    assert!(loser.success);

    let mut master_fields = serde_json::Map::new();
    master_fields.insert("BillingCity".to_string(), json!("San Francisco"));

    let merge_result = soap_client
        .merge(
            "Account",
            &master.id,
            &[&loser.id],
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

    let loser_result = rest_client.get("Account", &loser.id, None).await;
    assert!(loser_result.is_err());

    rest_client.delete("Account", &master.id).await?;

    Ok(())
}
