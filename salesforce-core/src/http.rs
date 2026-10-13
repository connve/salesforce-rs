//! Shared HTTP client utilities for Salesforce API clients.
//!
//! This module provides common functionality for building HTTP clients with
//! authentication headers, connection pooling, and timeout configuration.
//! The HTTP client is cached and reused across requests, only rebuilding
//! when the access token changes (e.g., after a refresh or re-authentication).

use crate::client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use secrecy::{ExposeSecret, SecretString};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{PoisonError, RwLock};
use std::time::Duration;

/// Error type for HTTP client building.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Failed to retrieve a usable access token from the auth client.
    #[error("Failed to get access token: {source}")]
    Auth {
        #[source]
        source: client::Error,
    },

    /// Failed to build the HTTP client.
    #[error("Failed to build HTTP client: {source}")]
    Build {
        #[source]
        source: reqwest::Error,
    },
}

/// Cached HTTP client paired with the token and header-set it was built for.
#[derive(Debug)]
pub(crate) struct CachedHttpClient {
    /// The cached token used to build the current client. Redacted from
    /// `Debug` output, like every API client that holds this cache.
    token: SecretString,
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

        // The cache only ever holds a fully built client, so a panic in another
        // thread can't leave it half-written: recover from poisoning instead of
        // failing every later request.

        // Fast path: check if cached client has the same token and headers.
        {
            let cache = self.cache.read().unwrap_or_else(PoisonError::into_inner);
            if let Some(cached) = cache.as_ref() {
                if cached.token.expose_secret() == token.expose_secret()
                    && cached.headers_hash == headers_hash
                {
                    return Ok(cached.client.clone());
                }
            }
        }

        // Token or headers changed (or first call): build a new client.
        let client = build_http_client(
            token.expose_secret(),
            connect_timeout,
            request_timeout,
            extra_headers,
        )?;

        {
            let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
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
fn build_http_client(
    token: &str,
    connect_timeout: Duration,
    request_timeout: Duration,
    extra_headers: &HeaderMap,
) -> Result<reqwest::Client, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, authorization_header(token)?);
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

/// `Bearer <token>`, marked sensitive so `Debug` output of the header (and of
/// the `reqwest::Client` holding it) redacts the token.
fn authorization_header(token: &str) -> Result<HeaderValue, Error> {
    let mut value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| Error::Auth {
        source: client::Error::InvalidAccessToken,
    })?;
    value.set_sensitive(true);
    Ok(value)
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

/// A value rejected by [`check_path_segments`]. Each operation module converts
/// it into its own `Error::InvalidPathSegment` with `From`, so `?` works.
#[cfg(any(feature = "restapi", feature = "bulkapi"))]
#[derive(Debug)]
pub(crate) struct InvalidPathSegment {
    pub(crate) segment: String,
}

/// Rejects the first value that can't be sent as a single URL path segment:
/// empty, `.`, `..`, or containing control characters.
///
/// The generated clients percent-encode `/` but not dots, so `..` would be
/// resolved by the URL parser and hit a different endpoint.
#[cfg(any(feature = "restapi", feature = "bulkapi"))]
pub(crate) fn check_path_segments(segments: &[&str]) -> Result<(), InvalidPathSegment> {
    let invalid = segments.iter().find(|segment| {
        segment.is_empty()
            || **segment == "."
            || **segment == ".."
            || segment.contains(char::is_control)
    });
    match invalid {
        Some(segment) => Err(InvalidPathSegment {
            segment: (*segment).to_string(),
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderName;

    #[cfg(any(feature = "restapi", feature = "bulkapi"))]
    #[test]
    fn test_check_path_segments_rejects_dot_segments() {
        for bad in ["", ".", "..", "001\n"] {
            assert!(matches!(
                check_path_segments(&["Account", bad]),
                Err(InvalidPathSegment { ref segment }) if segment == bad
            ));
        }
    }

    #[cfg(any(feature = "restapi", feature = "bulkapi"))]
    #[test]
    fn test_check_path_segments_accepts_ids() {
        assert!(check_path_segments(&["Account", "001xx000003DGb2AAG", "a.b"]).is_ok());
    }

    #[test]
    fn test_authorization_header_is_sensitive() {
        let value = authorization_header("token").expect("valid token");
        assert!(value.is_sensitive());
        assert_eq!(value, "Bearer token");
    }

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
