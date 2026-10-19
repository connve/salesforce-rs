//! Shared test utilities for integration tests.
//!
//! Provides authentication helpers and a skip macro for tests that require
//! Salesforce credentials via a JSON file path in `SFDC_CREDENTIALS`.

use salesforce_core::client;
use std::env;

/// Environment variable pointing to the credentials JSON file.
const CREDENTIALS_ENV: &str = "SFDC_CREDENTIALS";

/// Returns true if the credentials environment variable is set.
pub fn credentials_available() -> bool {
    env::var(CREDENTIALS_ENV).is_ok()
}

/// Skips the current test if Salesforce credentials are not configured.
///
/// Must be called at the start of every integration test. The test function
/// must return `Result<(), Box<dyn std::error::Error>>`.
#[macro_export]
macro_rules! skip_if_no_credentials {
    () => {
        if !common::credentials_available() {
            eprintln!(
                "Skipping integration test: set SFDC_CREDENTIALS to a JSON file path to run."
            );
            return Ok(());
        }
    };
}

/// Reads the credentials JSON file named by `SFDC_CREDENTIALS`.
pub fn credentials() -> Result<client::Credentials, Box<dyn std::error::Error>> {
    let path = env::var(CREDENTIALS_ENV)?;
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

/// Creates an authenticated Salesforce client by loading credentials from the
/// JSON file specified in the `SFDC_CREDENTIALS` environment variable.
///
/// The JSON file should contain:
/// ```json
/// {
///   "client_id": "...",
///   "client_secret": "...",
///   "instance_url": "https://your-instance.my.salesforce.com",
///   "tenant_id": "..."
/// }
/// ```
pub async fn auth_client() -> Result<client::Client, Box<dyn std::error::Error>> {
    let client = client::Client::builder()
        .credentials(credentials()?)
        .build()?
        .connect()
        .await?;
    Ok(client)
}
