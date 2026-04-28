//! Integration tests for authentication and token management.

mod common;

use salesforce_core::client::{self, Credentials};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn test_client_credentials_connect() -> Result {
    skip_if_no_credentials!();

    let client = common::auth_client().await?;

    assert!(client.instance_url.is_some());
    assert!(client.tenant_id.is_some());

    let token = client.access_token().await?;
    assert!(!token.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_access_token_is_cached() -> Result {
    skip_if_no_credentials!();

    let client = common::auth_client().await?;

    let token1 = client.access_token().await?;
    let token2 = client.access_token().await?;
    assert_eq!(token1, token2);

    Ok(())
}

#[tokio::test]
async fn test_reconnect() -> Result {
    skip_if_no_credentials!();

    let mut client = common::auth_client().await?;
    let token_before = client.access_token().await?;

    client.reconnect().await?;
    let token_after = client.access_token().await?;

    assert!(!token_before.is_empty());
    assert!(!token_after.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_invalid_credentials_rejected() -> Result {
    let result = client::Builder::new()
        .credentials(Credentials {
            client_id: "invalid_id".to_string(),
            client_secret: Some("invalid_secret".to_string()),
            username: None,
            password: None,
            instance_url: "https://login.salesforce.com".to_string(),
            tenant_id: "invalid_tenant".to_string(),
        })
        .build()?
        .connect()
        .await;

    assert!(result.is_err());

    Ok(())
}
