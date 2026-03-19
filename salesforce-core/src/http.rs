//! Shared HTTP client utilities for Salesforce API clients.
//!
//! This module provides common functionality for building HTTP clients with
//! authentication headers, connection pooling, and timeout configuration.

use crate::client;
use std::time::Duration;

/// Error type for HTTP client building.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Failed to retrieve access token from auth client.
    #[error("Failed to get access token: {source}")]
    Auth {
        #[source]
        source: client::Error,
    },

    /// Failed to construct HTTP headers (e.g., invalid token format).
    #[error("Failed to create HTTP headers")]
    InvalidHeader,

    /// Failed to build the HTTP client.
    #[error("Failed to build HTTP client: {source}")]
    Build {
        #[source]
        source: reqwest::Error,
    },
}

/// Builds an HTTP client configured for Salesforce API requests.
///
/// This function creates a `reqwest::Client` with:
/// - Bearer token authentication headers
/// - Configurable connection and request timeouts
/// - TCP keepalive for connection health
/// - Connection pooling with idle timeout and max connections per host
///
/// # Arguments
///
/// * `auth_client` - The authenticated Salesforce client to get the access token from
/// * `connect_timeout` - Timeout for establishing connections
/// * `request_timeout` - Timeout for completing requests
///
/// # Returns
///
/// A configured `reqwest::Client` ready for API requests.
///
/// # Errors
///
/// Returns an error if token retrieval fails, header construction fails,
/// or the HTTP client cannot be built.
pub async fn build_http_client(
    auth_client: &client::Client,
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<reqwest::Client, Error> {
    let token = auth_client
        .access_token()
        .await
        .map_err(|source| Error::Auth { source })?;

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| Error::InvalidHeader)?,
    );

    reqwest::ClientBuilder::new()
        .default_headers(headers)
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .tcp_keepalive(Duration::from_secs(crate::DEFAULT_TCP_KEEPALIVE_SECS))
        .pool_max_idle_per_host(crate::DEFAULT_POOL_MAX_IDLE_PER_HOST)
        .pool_idle_timeout(Duration::from_secs(crate::DEFAULT_POOL_IDLE_TIMEOUT_SECS))
        .build()
        .map_err(|source| Error::Build { source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_source_chain_preserved() {
        let auth_error = client::Error::LockError;
        let error = Error::Auth { source: auth_error };

        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }
}
