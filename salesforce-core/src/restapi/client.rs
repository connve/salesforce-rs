//! REST API client wrapper.

use crate::client;
use reqwest::header::{HeaderMap, HeaderName, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use std::sync::Arc;
use std::time::Duration;

use crate::{DEFAULT_API_VERSION, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_REQUEST_TIMEOUT_SECS};

/// Headers that callers must not set via `default_headers` or per-call overrides.
///
/// `Authorization` is owned by the auth client and `Content-Type`/`Accept` are
/// controlled by the generated API client per endpoint. Allowing overrides
/// would silently break requests.
const FORBIDDEN_HEADERS: &[HeaderName] = &[AUTHORIZATION, CONTENT_TYPE, ACCEPT];

/// Returns the first reserved header name in `headers`, if any.
pub(crate) fn forbidden_header(headers: &HeaderMap) -> Option<String> {
    headers.keys().find_map(|name| {
        if FORBIDDEN_HEADERS.iter().any(|f| f == name) {
            Some(name.as_str().to_string())
        } else {
            None
        }
    })
}

/// Client for Salesforce REST API operations.
///
/// This client wraps the authenticated Salesforce client and provides
/// access to REST API resources including SObject CRUD, queries, and searches.
#[derive(Clone)]
pub struct Client {
    pub(crate) auth_client: Arc<client::Client>,
    pub(crate) api_version: String,
    pub(crate) connect_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) default_headers: HeaderMap,
    pub(crate) http_cache: Arc<crate::http::HttpClientCache>,
}

/// Error type for REST API client builder.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Failed to build HTTP client.
    #[error("Failed to build HTTP client.")]
    HttpClient {
        /// The underlying reqwest error.
        #[source]
        source: reqwest::Error,
    },

    /// A header supplied via `default_headers` is reserved by the SDK and
    /// cannot be overridden.
    #[error("Header `{name}` is managed by the SDK and cannot be overridden")]
    InvalidHeader {
        /// The reserved header name that was rejected.
        name: String,
    },
}

impl Error {
    /// Returns `true` if the error is transient and the operation could
    /// succeed if retried.
    ///
    /// Builder errors reflect configuration problems and are never retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::HttpClient { .. } | Error::InvalidHeader { .. } => false,
        }
    }
}

/// Builder for creating a REST API client.
pub struct ClientBuilder {
    auth_client: client::Client,
    api_version: Option<String>,
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    default_headers: HeaderMap,
}

impl ClientBuilder {
    /// Creates a new REST API client builder.
    ///
    /// # Arguments
    ///
    /// * `auth_client` - An authenticated Salesforce client
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let auth_client = client::Builder::new()
    ///     .credentials(Credentials {
    ///         client_id: "...".to_string(),
    ///         client_secret: Some("...".to_string()),
    ///         username: None,
    ///         password: None,
    ///         instance_url: "https://your-instance.salesforce.com".to_string(),
    ///         tenant_id: "...".to_string(),
    ///     })
    ///     .build()?
    ///     .connect()
    ///     .await?;
    ///
    /// let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(auth_client: client::Client) -> Self {
        Self {
            auth_client,
            api_version: None,
            connect_timeout: None,
            request_timeout: None,
            default_headers: HeaderMap::new(),
        }
    }

    /// Sets the Salesforce API version to use.
    ///
    /// Defaults to the latest supported version if not specified.
    ///
    /// # Arguments
    ///
    /// * `version` - The API version (e.g., "65.0")
    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(version.into());
        self
    }

    /// Sets the connection timeout for HTTP requests.
    ///
    /// Defaults to 30 seconds if not specified.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The connection timeout duration
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Sets the request timeout for HTTP requests.
    ///
    /// Defaults to 120 seconds if not specified.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The request timeout duration
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// Sets default HTTP headers to send on every request issued through this
    /// client.
    ///
    /// Useful for Salesforce-specific request headers such as
    /// `Sforce-Duplicate-Rule-Header`, `Sforce-Auto-Assign`, or
    /// `Sforce-Call-Options`.
    ///
    /// Headers managed by the SDK (`Authorization`, `Content-Type`, `Accept`)
    /// are rejected at [`build`](Self::build) time.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Builder::new()
    /// #     .credentials(Credentials {
    /// #         client_id: "...".to_string(),
    /// #         client_secret: Some("...".to_string()),
    /// #         username: None,
    /// #         password: None,
    /// #         instance_url: "https://localhost".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let mut headers = HeaderMap::new();
    /// headers.insert(
    ///     HeaderName::from_static("sforce-duplicate-rule-header"),
    ///     HeaderValue::from_static("allowSave=true"),
    /// );
    ///
    /// let rest_client = restapi::ClientBuilder::new(auth_client)
    ///     .default_headers(headers)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn default_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = headers;
        self
    }

    /// Builds the REST API client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn build(self) -> Result<Client, Error> {
        if let Some(name) = forbidden_header(&self.default_headers) {
            return Err(Error::InvalidHeader { name });
        }

        Ok(Client {
            auth_client: Arc::new(self.auth_client),
            api_version: self
                .api_version
                .unwrap_or_else(|| DEFAULT_API_VERSION.to_string()),
            connect_timeout: self
                .connect_timeout
                .unwrap_or_else(|| Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)),
            request_timeout: self
                .request_timeout
                .unwrap_or_else(|| Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS)),
            default_headers: self.default_headers,
            http_cache: Arc::new(crate::http::HttpClientCache::new()),
        })
    }
}

impl Client {
    /// Returns a reference to the authenticated Salesforce client.
    pub fn auth_client(&self) -> &Arc<client::Client> {
        &self.auth_client
    }

    /// Returns the configured API version.
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Returns the base URL for API requests.
    ///
    /// This constructs the URL in the format:
    /// `https://<instance>.salesforce.com/services/data/v<version>`
    pub(crate) fn base_url(&self) -> Result<String, client::Error> {
        let instance_url = self
            .auth_client
            .instance_url
            .as_ref()
            .ok_or(client::Error::NotConnected)?;

        Ok(format!(
            "{}/services/data/v{}",
            instance_url, self.api_version
        ))
    }

    /// Returns the connection timeout for HTTP requests.
    pub(crate) fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Returns the request timeout for HTTP requests.
    pub(crate) fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Gets an HTTP client with authentication and client-level default
    /// headers for API requests.
    ///
    /// Returns a cached client when the token and headers haven't changed,
    /// reusing TCP connections and TLS sessions for better performance.
    pub(crate) async fn get_http_client(&self) -> Result<reqwest::Client, crate::http::Error> {
        self.http_cache
            .get(
                self.auth_client.as_ref(),
                self.connect_timeout(),
                self.request_timeout(),
                &self.default_headers,
            )
            .await
    }

    /// Builds a fresh (uncached) HTTP client whose default headers are the
    /// client-level headers merged with `per_call`.
    ///
    /// Used by request builders that attach per-call Salesforce headers (for
    /// example `Sforce-Duplicate-Rule-Header`) without mutating the long-lived
    /// cached client. Callers are responsible for validating `per_call`
    /// against [`forbidden_header`] before invoking.
    pub(crate) async fn get_http_client_with_extra(
        &self,
        per_call: &HeaderMap,
    ) -> Result<reqwest::Client, crate::http::Error> {
        let token = self
            .auth_client
            .access_token()
            .await
            .map_err(|source| crate::http::Error::Auth { source })?;

        let mut merged = self.default_headers.clone();
        for (name, value) in per_call.iter() {
            merged.append(name.clone(), value.clone());
        }

        crate::http::build_http_client(
            &token,
            self.connect_timeout(),
            self.request_timeout(),
            &merged,
        )
    }

    /// Access SObject CRUD operations.
    ///
    /// # Returns
    ///
    /// A reference to the client itself, which implements all SObject operations.
    pub fn sobject(&self) -> &Self {
        self
    }

    /// Access Composite API operations for bulk record operations.
    ///
    /// # Returns
    ///
    /// A reference to the client itself, which implements all Composite operations.
    pub fn composite(&self) -> &Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn test_forbidden_header_rejects_authorization() {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        assert_eq!(forbidden_header(&h).as_deref(), Some("authorization"));
    }

    #[test]
    fn test_forbidden_header_rejects_content_type() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(forbidden_header(&h).as_deref(), Some("content-type"));
    }

    #[test]
    fn test_forbidden_header_rejects_accept() {
        let mut h = HeaderMap::new();
        h.insert(ACCEPT, HeaderValue::from_static("application/xml"));
        assert_eq!(forbidden_header(&h).as_deref(), Some("accept"));
    }

    #[test]
    fn test_forbidden_header_accepts_sforce_headers() {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("sforce-duplicate-rule-header"),
            HeaderValue::from_static("allowSave=true"),
        );
        h.insert(
            HeaderName::from_static("sforce-auto-assign"),
            HeaderValue::from_static("FALSE"),
        );
        assert!(forbidden_header(&h).is_none());
    }
}
