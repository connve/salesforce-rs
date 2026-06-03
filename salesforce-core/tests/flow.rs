//! Integration tests for Flow invocation via the Custom Invocable Actions API.

mod common;

use salesforce_core::restapi::{ClientBuilder, FlowInvokeRequest};
use serde_json::json;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn test_invoke_flow_invalid_name() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let result = client
        .invoke_flow("NonExistent_Flow_Name_99", json!({}))
        .await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_invoke_flow_batch_invalid_name() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let request = FlowInvokeRequest {
        inputs: vec![serde_json::Map::new()],
    };

    let result = client
        .invoke_flow_batch("NonExistent_Flow_Name_99", &request)
        .await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_invoke_flow_rejects_non_object_input() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;

    let result = client.invoke_flow("Any_Flow", json!("not an object")).await;
    assert!(matches!(
        result,
        Err(salesforce_core::restapi::FlowError::InvalidInputType { .. })
    ));

    Ok(())
}
