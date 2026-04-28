//! Integration tests for the Composite API (batch operations).

mod common;

use salesforce_core::restapi::{
    ClientBuilder, CompositeCollectionCreateRequest, CompositeCollectionRetrieveRequest,
    CompositeCollectionUpdateRequest, CompositeRecordRequest, CompositeTreeRequest,
};
use serde_json::json;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Helper to extract record identifiers from composite create results.
fn extract_ids(
    results: &salesforce_core::restapi::CompositeCollectionCreateResponse,
) -> Vec<String> {
    results
        .iter()
        .filter(|r| r.success)
        .filter_map(|r| r.id.clone())
        .collect()
}

/// Helper to batch-delete records by a comma-separated identifier string.
async fn cleanup(client: &salesforce_core::restapi::Client, ids: &[String]) -> Result {
    if ids.is_empty() {
        return Ok(());
    }
    let id_str = ids.join(",");
    client.delete_records(&id_str, Some(false)).await?;
    Ok(())
}

#[tokio::test]
async fn test_composite_create_and_delete() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let records: Vec<CompositeRecordRequest> = (0..3)
        .map(|i| {
            serde_json::from_value(json!({
                "attributes": {"type": "Account"},
                "Name": format!("Composite Test {}", i)
            }))
        })
        .collect::<std::result::Result<_, _>>()?;

    let create_request = CompositeCollectionCreateRequest {
        all_or_none: true,
        records,
    };

    let results = client.create_records(&create_request).await?;
    assert_eq!(results.len(), 3);

    let ids = extract_ids(&results);
    assert_eq!(ids.len(), 3);

    let delete_results = client.delete_records(&ids.join(","), Some(false)).await?;
    assert_eq!(delete_results.len(), 3);
    for r in delete_results.iter() {
        assert!(r.success);
    }

    Ok(())
}

#[tokio::test]
async fn test_composite_update() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let records: Vec<CompositeRecordRequest> = (0..2)
        .map(|i| {
            serde_json::from_value(json!({
                "attributes": {"type": "Account"},
                "Name": format!("Update Test {}", i),
                "Industry": "Technology"
            }))
        })
        .collect::<std::result::Result<_, _>>()?;

    let create_request = CompositeCollectionCreateRequest {
        all_or_none: true,
        records,
    };
    let created = client.create_records(&create_request).await?;
    let ids = extract_ids(&created);
    assert_eq!(ids.len(), 2);

    let id0 = ids.first().ok_or("missing first created record id")?;
    let id1 = ids.get(1).ok_or("missing second created record id")?;

    let update_request: CompositeCollectionUpdateRequest = serde_json::from_value(json!({
        "allOrNone": true,
        "records": [
            {"attributes": {"type": "Account"}, "id": id0, "Industry": "Finance"},
            {"attributes": {"type": "Account"}, "id": id1, "Industry": "Healthcare"}
        ]
    }))?;
    let update_results = client.update_records(&update_request).await?;
    assert_eq!(update_results.len(), 2);
    for r in update_results.iter() {
        assert!(r.success);
    }

    let acc0 = client.get("Account", id0, Some("Industry")).await?;
    assert_eq!(
        acc0.get("Industry").and_then(|v| v.as_str()),
        Some("Finance")
    );

    let acc1 = client.get("Account", id1, Some("Industry")).await?;
    assert_eq!(
        acc1.get("Industry").and_then(|v| v.as_str()),
        Some("Healthcare")
    );

    cleanup(&client, &ids).await?;

    Ok(())
}

#[tokio::test]
async fn test_composite_retrieve() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let records: Vec<CompositeRecordRequest> = (0..2)
        .map(|i| {
            serde_json::from_value(json!({
                "attributes": {"type": "Account"},
                "Name": format!("Retrieve Test {}", i)
            }))
        })
        .collect::<std::result::Result<_, _>>()?;

    let create_request = CompositeCollectionCreateRequest {
        all_or_none: true,
        records,
    };
    let created = client.create_records(&create_request).await?;
    let ids = extract_ids(&created);

    let retrieve_request = CompositeCollectionRetrieveRequest {
        ids: ids.clone(),
        fields: vec!["Id".to_string(), "Name".to_string()],
    };
    let retrieved = client.get_records("Account", &retrieve_request).await?;
    assert_eq!(retrieved.len(), 2);

    cleanup(&client, &ids).await?;

    Ok(())
}

#[tokio::test]
async fn test_composite_tree_create() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let tree_request: CompositeTreeRequest = serde_json::from_value(json!({
        "records": [{
            "attributes": {"type": "Account", "referenceId": "ref1"},
            "Name": "Tree Test Account",
            "Contacts": {
                "records": [{
                    "attributes": {"type": "Contact", "referenceId": "ref2"},
                    "LastName": "TreeContact"
                }]
            }
        }]
    }))?;

    let result = client.create_record_tree("Account", &tree_request).await?;
    assert!(!result.has_errors);
    assert!(result.results.len() >= 2);

    // Delete child records before parent to respect foreign key constraints.
    let contact_id = result
        .results
        .iter()
        .find(|r| r.reference_id == "ref2")
        .map(|r| r.id.clone())
        .ok_or("missing contact reference in tree response")?;

    let account_id = result
        .results
        .iter()
        .find(|r| r.reference_id == "ref1")
        .map(|r| r.id.clone())
        .ok_or("missing account reference in tree response")?;

    client.delete("Contact", &contact_id).await?;
    client.delete("Account", &account_id).await?;

    Ok(())
}
