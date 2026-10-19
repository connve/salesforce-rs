//! Integration tests for authentication and token management.

mod common;

use salesforce_core::client;
use salesforce_core::secrecy::ExposeSecret;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
#[ignore = "needs a Salesforce org in SFDC_CREDENTIALS"]
async fn test_client_credentials_connect() -> Result {
    let client = common::auth_client().await?;

    assert!(client.instance_url.is_some());
    assert!(client.tenant_id.is_some());

    let token = client.access_token().await?;
    assert!(!token.expose_secret().is_empty());

    Ok(())
}

#[tokio::test]
#[ignore = "needs a Salesforce org in SFDC_CREDENTIALS"]
async fn test_access_token_is_cached() -> Result {
    let client = common::auth_client().await?;

    let token1 = client.access_token().await?;
    let token2 = client.access_token().await?;
    assert_eq!(token1.expose_secret(), token2.expose_secret());

    Ok(())
}

#[tokio::test]
#[ignore = "needs a Salesforce org in SFDC_CREDENTIALS"]
async fn test_reconnect() -> Result {
    let mut client = common::auth_client().await?;
    let token_before = client.access_token().await?;

    client.reconnect().await?;
    let token_after = client.access_token().await?;

    assert!(!token_before.expose_secret().is_empty());
    assert!(!token_after.expose_secret().is_empty());

    Ok(())
}

#[tokio::test]
async fn test_invalid_credentials_rejected() -> Result {
    let result = client::Client::builder()
        .client_id("invalid_id")
        .client_secret("invalid_secret")
        .instance_url("https://login.salesforce.com")
        .build()?
        .connect()
        .await;

    assert!(result.is_err());

    Ok(())
}
