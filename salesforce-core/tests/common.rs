//! Helpers for live tests against the Salesforce org whose credentials JSON
//! file is named by `SFDC_CREDENTIALS`.
//!
//! Live tests are `#[ignore]`d; run them with `cargo test -- --ignored`.

use salesforce_core::client;
use std::env;

/// Environment variable pointing to the credentials JSON file.
const CREDENTIALS_ENV: &str = "SFDC_CREDENTIALS";

/// Reads the credentials JSON file named by `SFDC_CREDENTIALS`. Fails when
/// the variable is unset, so an ignored test run without it can't pass.
pub fn credentials() -> Result<client::Credentials, Box<dyn std::error::Error>> {
    let path = env::var(CREDENTIALS_ENV).map_err(|error| format!("{CREDENTIALS_ENV}: {error}"))?;
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
