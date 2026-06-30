//! SOAP API client that wraps the authentication client.

use crate::client;
use crate::http::HttpClientCache;
use std::sync::Arc;
use std::time::Duration;

/// Client for Salesforce SOAP API operations.
///
/// Provides access to SOAP-only operations such as record merging that are
/// not available through the REST API.
///
/// # Example
///
/// ```no_run
/// use salesforce_core::client::{self, Credentials};
/// use salesforce_core::soapapi::ClientBuilder;
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
/// let soap_client = ClientBuilder::new(auth_client).build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Client {
    pub(crate) auth_client: Arc<client::Client>,
    pub(crate) api_version: String,
    pub(crate) connect_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) http_cache: Arc<HttpClientCache>,
}

/// Error type for SOAP API client builder.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Failed to build the client.
    #[error("Failed to build SOAP API client")]
    Build,
}

impl Error {
    /// Returns `true` if the error is transient and the operation could
    /// succeed if retried.
    ///
    /// Builder errors reflect configuration problems and are never retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Build => false,
        }
    }
}

/// Builder for creating a SOAP API client.
pub struct ClientBuilder {
    auth_client: client::Client,
    api_version: Option<String>,
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
}

impl ClientBuilder {
    /// Creates a new builder for the SOAP API client.
    ///
    /// # Arguments
    ///
    /// * `auth_client` - An authenticated salesforce-core `Client` for OAuth token management.
    pub fn new(auth_client: client::Client) -> Self {
        Self {
            auth_client,
            api_version: None,
            connect_timeout: None,
            request_timeout: None,
        }
    }

    /// Sets the Salesforce API version to use.
    ///
    /// Defaults to the latest supported version if not specified.
    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(version.into());
        self
    }

    /// Sets the connection timeout for HTTP requests.
    ///
    /// Defaults to 30 seconds if not specified.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Sets the request timeout for HTTP requests.
    ///
    /// Defaults to 120 seconds if not specified.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// Builds the SOAP API client.
    pub fn build(self) -> Result<Client, Error> {
        Ok(Client {
            auth_client: Arc::new(self.auth_client),
            api_version: self
                .api_version
                .unwrap_or_else(|| crate::DEFAULT_API_VERSION.to_string()),
            connect_timeout: self
                .connect_timeout
                .unwrap_or(Duration::from_secs(crate::DEFAULT_CONNECT_TIMEOUT_SECS)),
            request_timeout: self
                .request_timeout
                .unwrap_or(Duration::from_secs(crate::DEFAULT_REQUEST_TIMEOUT_SECS)),
            http_cache: Arc::new(HttpClientCache::new()),
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

    /// Returns the SOAP endpoint URL.
    pub(crate) fn soap_url(&self) -> Result<String, client::Error> {
        let instance_url = self
            .auth_client
            .instance_url
            .as_ref()
            .ok_or(client::Error::NotConnected)?;

        Ok(format!(
            "{}/services/Soap/u/{}",
            instance_url, self.api_version
        ))
    }

    /// Gets a cached HTTP client with authentication headers for API requests.
    pub(crate) async fn get_http_client(&self) -> Result<reqwest::Client, crate::http::Error> {
        self.http_cache
            .get(
                self.auth_client.as_ref(),
                self.connect_timeout,
                self.request_timeout,
                &reqwest::header::HeaderMap::new(),
            )
            .await
    }
}
