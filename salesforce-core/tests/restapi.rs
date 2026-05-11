//! Integration tests for the REST API (SObject CRUD and Search).

mod common;

use salesforce_core::restapi::{ClientBuilder, MergeRequest};
use serde_json::json;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn test_sobject_crud_cycle() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let create_resp = client
        .create(
            "Account",
            json!({
                "Name": "Integration Test Account",
                "Industry": "Technology"
            }),
        )
        .await?;
    assert!(create_resp.success);
    assert!(!create_resp.id.is_empty());
    let id = create_resp.id.clone();

    let record = client.get("Account", &id, Some("Id,Name,Industry")).await?;
    assert_eq!(
        record.get("Name").and_then(|v| v.as_str()),
        Some("Integration Test Account")
    );
    assert_eq!(
        record.get("Industry").and_then(|v| v.as_str()),
        Some("Technology")
    );

    client
        .update("Account", &id, json!({"Industry": "Finance"}))
        .await?;

    let updated = client.get("Account", &id, Some("Id,Industry")).await?;
    assert_eq!(
        updated.get("Industry").and_then(|v| v.as_str()),
        Some("Finance")
    );

    client.delete("Account", &id).await?;

    let get_result = client.get("Account", &id, None).await;
    assert!(get_result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_describe_account() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let describe = client.describe("Account").await?;

    assert_eq!(describe.name, "Account");
    assert!(describe.queryable);
    assert!(!describe.fields.is_empty());

    let name_field = describe.fields.iter().find(|f| f.name == "Name");
    assert!(name_field.is_some());

    Ok(())
}

#[tokio::test]
async fn test_basic_info_account() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let info = client.basic_info("Account").await?;
    assert_eq!(info.object_describe.name, "Account");
    assert!(info.object_describe.queryable);

    Ok(())
}

#[tokio::test]
async fn test_create_invalid_sobject_type() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let result = client
        .create("NonExistentObject__c", json!({"Name": "test"}))
        .await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_merge_accounts() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let master = client
        .create(
            "Account",
            json!({
                "Name": "Merge Master Account",
                "Industry": "Technology"
            }),
        )
        .await?;
    assert!(master.success);

    let loser = client
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

    let request = MergeRequest {
        master_record: master_fields,
        record_ids_to_merge: vec![loser.id.clone()],
    };

    client.merge("Account", &master.id, &request).await?;

    let merged = client
        .get("Account", &master.id, Some("Id,Name,BillingCity"))
        .await?;
    assert_eq!(
        merged.get("BillingCity").and_then(|v| v.as_str()),
        Some("San Francisco")
    );

    let loser_result = client.get("Account", &loser.id, None).await;
    assert!(loser_result.is_err());

    client.delete("Account", &master.id).await?;

    Ok(())
}

#[tokio::test]
async fn test_search_sosl() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let create_resp = client
        .create("Account", json!({"Name": "SearchTestXYZ99"}))
        .await?;
    let id = create_resp.id.clone();

    // Salesforce SOSL indexing is asynchronous, so the record may not appear
    // in search results immediately. This test validates the endpoint works.
    let result = client
        .search("FIND {SearchTestXYZ99} IN NAME FIELDS RETURNING Account(Id, Name)")
        .await;
    assert!(result.is_ok());

    client.delete("Account", &id).await?;

    Ok(())
}
