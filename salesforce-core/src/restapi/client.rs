//! REST API client wrapper.

use crate::client;
use std::sync::Arc;
use std::time::Duration;

use crate::{DEFAULT_API_VERSION, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_REQUEST_TIMEOUT_SECS};

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
}

/// Builder for creating a REST API client.
pub struct ClientBuilder {
    auth_client: client::Client,
    api_version: Option<String>,
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
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

    /// Builds the REST API client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn build(self) -> Result<Client, Error> {
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

    /// Gets an HTTP client with authentication headers for API requests.
    ///
    /// This creates a new reqwest::Client with the current access token in the Authorization header.
    pub(crate) async fn get_http_client(&self) -> Result<reqwest::Client, crate::http::Error> {
        crate::http::get_http_client(
            self.auth_client.as_ref(),
            self.connect_timeout(),
            self.request_timeout(),
        )
        .await
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
