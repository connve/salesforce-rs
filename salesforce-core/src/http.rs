//! Shared HTTP client utilities for Salesforce API clients.
//!
//! This module provides common functionality for building HTTP clients with
//! authentication headers, connection pooling, and timeout configuration.
//! The HTTP client is cached and reused across requests, only rebuilding
//! when the access token changes (e.g., after a refresh or re-authentication).

use crate::client;
use std::sync::RwLock;
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

    /// Failed to acquire lock on HTTP client cache.
    #[error("Failed to acquire lock on HTTP client cache")]
    Lock,

    /// Failed to build the HTTP client.
    #[error("Failed to build HTTP client: {source}")]
    Build {
        #[source]
        source: reqwest::Error,
    },
}

/// Cached HTTP client paired with the token it was built for.
#[derive(Debug)]
pub(crate) struct CachedHttpClient {
    /// The cached token string used to build the current client.
    token: String,
    /// The cached reqwest::Client built with that token.
    client: reqwest::Client,
}

/// Thread-safe cache for an HTTP client that is rebuilt only when the token changes.
#[derive(Debug)]
pub(crate) struct HttpClientCache {
    cache: RwLock<Option<CachedHttpClient>>,
}

impl HttpClientCache {
    /// Creates a new empty cache.
    pub(crate) fn new() -> Self {
        Self {
            cache: RwLock::new(None),
        }
    }

    /// Returns a cached HTTP client, rebuilding only if the token has changed.
    pub(crate) async fn get(
        &self,
        auth_client: &client::Client,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<reqwest::Client, Error> {
        let token = auth_client
            .access_token()
            .await
            .map_err(|source| Error::Auth { source })?;

        // Fast path: check if cached client has the same token.
        {
            let cache = self.cache.read().map_err(|_| Error::Lock)?;
            if let Some(cached) = cache.as_ref() {
                if cached.token == token {
                    return Ok(cached.client.clone());
                }
            }
        }

        // Token changed (or first call): build a new client.
        let client = build_http_client(&token, connect_timeout, request_timeout)?;

        {
            let mut cache = self.cache.write().map_err(|_| Error::Lock)?;
            *cache = Some(CachedHttpClient {
                token,
                client: client.clone(),
            });
        }

        Ok(client)
    }
}

/// Builds an HTTP client with the given bearer token and timeout configuration.
fn build_http_client(
    token: &str,
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<reqwest::Client, Error> {
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
