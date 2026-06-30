//! Shared HTTP client utilities for Salesforce API clients.
//!
//! This module provides common functionality for building HTTP clients with
//! authentication headers, connection pooling, and timeout configuration.
//! The HTTP client is cached and reused across requests, only rebuilding
//! when the access token changes (e.g., after a refresh or re-authentication).

use crate::client;
use reqwest::header::{HeaderMap, AUTHORIZATION};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::RwLock;
use std::time::Duration;

/// Error type for HTTP client building.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
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

#[cfg(feature = "restapi")]
impl Error {
    /// Returns `true` if the error is transient and the operation could
    /// succeed if retried.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Auth { source } => source.is_retryable(),
            Error::Build { source } => source.is_timeout() || source.is_connect(),
            Error::InvalidHeader | Error::Lock => false,
        }
    }
}

/// Cached HTTP client paired with the token and header-set it was built for.
#[derive(Debug)]
pub(crate) struct CachedHttpClient {
    /// The cached token string used to build the current client.
    token: String,
    /// Hash of the client-level extra headers the cached client was built with.
    headers_hash: u64,
    /// The cached reqwest::Client built with that token + headers.
    client: reqwest::Client,
}

/// Thread-safe cache for an HTTP client that is rebuilt only when the token or
/// client-level extra headers change.
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

    /// Returns a cached HTTP client, rebuilding only if the token or
    /// client-level headers have changed. Pass `&HeaderMap::new()` for callers
    /// that don't need extra headers.
    pub(crate) async fn get(
        &self,
        auth_client: &client::Client,
        connect_timeout: Duration,
        request_timeout: Duration,
        extra_headers: &HeaderMap,
    ) -> Result<reqwest::Client, Error> {
        let token = auth_client
            .access_token()
            .await
            .map_err(|source| Error::Auth { source })?;
        let headers_hash = hash_header_map(extra_headers);

        // Fast path: check if cached client has the same token and headers.
        {
            let cache = self.cache.read().map_err(|_| Error::Lock)?;
            if let Some(cached) = cache.as_ref() {
                if cached.token == token && cached.headers_hash == headers_hash {
                    return Ok(cached.client.clone());
                }
            }
        }

        // Token or headers changed (or first call): build a new client.
        let client = build_http_client(&token, connect_timeout, request_timeout, extra_headers)?;

        {
            let mut cache = self.cache.write().map_err(|_| Error::Lock)?;
            *cache = Some(CachedHttpClient {
                token,
                headers_hash,
                client: client.clone(),
            });
        }

        Ok(client)
    }
}

/// Builds an HTTP client with the given bearer token, extra headers, and
/// timeout configuration.
pub(crate) fn build_http_client(
    token: &str,
    connect_timeout: Duration,
    request_timeout: Duration,
    extra_headers: &HeaderMap,
) -> Result<reqwest::Client, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| Error::InvalidHeader)?,
    );
    for (name, value) in extra_headers.iter() {
        headers.append(name.clone(), value.clone());
    }

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

/// Order-independent hash over a [`HeaderMap`], used as part of the cache key.
fn hash_header_map(headers: &HeaderMap) -> u64 {
    let mut entries: Vec<(&str, &[u8])> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_bytes()))
        .collect();
    entries.sort_unstable();
    let mut hasher = DefaultHasher::new();
    entries.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderName, HeaderValue};

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

    #[test]
    fn test_hash_header_map_is_order_independent() {
        let mut a = HeaderMap::new();
        a.insert(
            HeaderName::from_static("sforce-duplicate-rule-header"),
            HeaderValue::from_static("allowSave=true"),
        );
        a.insert(
            HeaderName::from_static("sforce-auto-assign"),
            HeaderValue::from_static("FALSE"),
        );

        let mut b = HeaderMap::new();
        b.insert(
            HeaderName::from_static("sforce-auto-assign"),
            HeaderValue::from_static("FALSE"),
        );
        b.insert(
            HeaderName::from_static("sforce-duplicate-rule-header"),
            HeaderValue::from_static("allowSave=true"),
        );

        assert_eq!(hash_header_map(&a), hash_header_map(&b));
    }
}
