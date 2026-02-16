//! Bulk API v2.0 client that wraps the authentication client.

use crate::client;
use std::sync::Arc;

/// Client for Salesforce Bulk API v2.0.
///
/// This client wraps the authentication client and provides access to
/// bulk query and ingest operations. It automatically handles OAuth token
/// management and refresh.
///
/// # Example
///
/// ```no_run
/// use salesforce_core::client::{self, Credentials};
/// use salesforce_core::bulkapi::ClientBuilder;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // First, create and connect the auth client
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
/// // Create a Bulk API client with default API version
/// let bulk_client = ClientBuilder::new(auth_client.clone()).build();
///
/// // Or specify a custom API version
/// let bulk_client_custom = ClientBuilder::new(auth_client)
///     .api_version("64.0")
///     .build();
///
/// // Use query operations
/// let query_client = bulk_client.query();
///
/// // Use ingest operations
/// let ingest_client = bulk_client.ingest();
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Client {
    auth_client: Arc<client::Client>,
    api_version: String,
    connect_timeout: std::time::Duration,
    request_timeout: std::time::Duration,
}

/// Builder for creating a Bulk API client.
#[derive(Debug)]
pub struct ClientBuilder {
    auth_client: client::Client,
    api_version: Option<String>,
    connect_timeout: Option<std::time::Duration>,
    request_timeout: Option<std::time::Duration>,
}

impl ClientBuilder {
    /// Creates a new builder for the Bulk API client.
    ///
    /// # Arguments
    ///
    /// * `auth_client` - An authenticated salesforce-core `Client` for OAuth token management
    ///
    /// # Returns
    ///
    /// A `Builder` instance that can be configured with optional settings before calling `build()`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::bulkapi::ClientBuilder;
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
    /// // Use default API version
    /// let bulk_client = ClientBuilder::new(auth_client.clone()).build();
    ///
    /// // Or specify a custom version
    /// let bulk_client_custom = ClientBuilder::new(auth_client)
    ///     .api_version("64.0")
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub fn new(auth_client: client::Client) -> Self {
        Self {
            auth_client,
            api_version: None,
            connect_timeout: None,
            request_timeout: None,
        }
    }

    /// Sets the API version for the Bulk API client.
    ///
    /// # Arguments
    ///
    /// * `version` - Salesforce API version (e.g., "65.0")
    ///
    /// # Returns
    ///
    /// `Self` for method chaining.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client::{self, Credentials};
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Builder::new()
    /// #     .credentials(Credentials {
    /// #         client_id: "...".to_string(),
    /// #         client_secret: Some("...".to_string()),
    /// #         username: None,
    /// #         password: None,
    /// #         instance_url: "https://your-instance.salesforce.com".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client)
    ///     .api_version("64.0")
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(version.into());
        self
    }

    /// Sets the connection timeout for HTTP requests.
    ///
    /// This controls how long to wait when establishing a connection to Salesforce.
    /// If not specified, defaults to [`crate::DEFAULT_CONNECT_TIMEOUT_SECS`] seconds.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Duration to wait for connection establishment
    ///
    /// # Returns
    ///
    /// The builder for method chaining.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client::{self, Credentials};
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # use std::time::Duration;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Builder::new()
    /// #     .credentials(Credentials {
    /// #         client_id: "...".to_string(),
    /// #         client_secret: Some("...".to_string()),
    /// #         username: None,
    /// #         password: None,
    /// #         instance_url: "https://your-instance.salesforce.com".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client)
    ///     .connect_timeout(Duration::from_secs(60))
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Sets the request timeout for HTTP requests.
    ///
    /// This controls how long to wait for a complete request/response cycle.
    /// If not specified, defaults to [`crate::DEFAULT_REQUEST_TIMEOUT_SECS`] seconds for bulk operations.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Duration to wait for request completion
    ///
    /// # Returns
    ///
    /// The builder for method chaining.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client::{self, Credentials};
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # use std::time::Duration;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Builder::new()
    /// #     .credentials(Credentials {
    /// #         client_id: "...".to_string(),
    /// #         client_secret: Some("...".to_string()),
    /// #         username: None,
    /// #         password: None,
    /// #         instance_url: "https://your-instance.salesforce.com".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client)
    ///     .request_timeout(Duration::from_secs(300))
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn request_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// Builds the Bulk API client.
    ///
    /// If no API version was specified, uses the default version from `crate::DEFAULT_API_VERSION`.
    ///
    /// # Returns
    ///
    /// A configured `Client` instance ready for use.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client::{self, Credentials};
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Builder::new()
    /// #     .credentials(Credentials {
    /// #         client_id: "...".to_string(),
    /// #         client_secret: Some("...".to_string()),
    /// #         username: None,
    /// #         password: None,
    /// #         instance_url: "https://your-instance.salesforce.com".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self) -> Client {
        Client {
            auth_client: Arc::new(self.auth_client),
            api_version: self
                .api_version
                .unwrap_or_else(|| crate::DEFAULT_API_VERSION.to_string()),
            connect_timeout: self
                .connect_timeout
                .unwrap_or(std::time::Duration::from_secs(
                    crate::DEFAULT_CONNECT_TIMEOUT_SECS,
                )),
            request_timeout: self
                .request_timeout
                .unwrap_or(std::time::Duration::from_secs(
                    crate::DEFAULT_REQUEST_TIMEOUT_SECS,
                )),
        }
    }
}

impl Client {
    /// Returns a reference to the authentication client.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub fn auth_client(&self) -> &client::Client {
        &self.auth_client
    }

    /// Returns the API version being used.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Returns the configured connection timeout.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub(crate) fn connect_timeout(&self) -> std::time::Duration {
        self.connect_timeout
    }

    /// Returns the configured request timeout.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub(crate) fn request_timeout(&self) -> std::time::Duration {
        self.request_timeout
    }

    /// Creates a query client for bulk query operations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client::{self, Credentials};
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Builder::new()
    /// #     .credentials(Credentials {
    /// #         client_id: "...".to_string(),
    /// #         client_secret: Some("...".to_string()),
    /// #         username: None,
    /// #         password: None,
    /// #         instance_url: "https://your-instance.salesforce.com".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build();
    ///
    /// let query_client = bulk_client.query();
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub fn query(&self) -> super::query::QueryClient {
        super::query::QueryClient::new(self.clone())
    }

    /// Creates an ingest client for bulk ingest operations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client::{self, Credentials};
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Builder::new()
    /// #     .credentials(Credentials {
    /// #         client_id: "...".to_string(),
    /// #         client_secret: Some("...".to_string()),
    /// #         username: None,
    /// #         password: None,
    /// #         instance_url: "https://your-instance.salesforce.com".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build();
    ///
    /// let ingest_client = bulk_client.ingest();
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub fn ingest(&self) -> super::ingest::IngestClient {
        super::ingest::IngestClient::new(self.clone())
    }

    /// Internal helper to get the base URL for Bulk API.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use oauth2::basic::BasicTokenResponse;
    use oauth2::{AccessToken, EmptyExtraTokenFields};

    fn create_mock_auth_client() -> client::Client {
        let mut client = client::Builder::new()
            .credentials(client::Credentials {
                client_id: "test_client_id".to_string(),
                client_secret: Some("test_secret".to_string()),
                username: None,
                password: None,
                instance_url: "https://test.salesforce.com".to_string(),
                tenant_id: "test_tenant".to_string(),
            })
            .build()
            .unwrap();

        // Set up token state for testing
        let token = BasicTokenResponse::new(
            AccessToken::new("test_access_token".to_string()),
            oauth2::basic::BasicTokenType::Bearer,
            EmptyExtraTokenFields {},
        );
        let token_state = client::TokenState::new(token).unwrap();
        client.token_state = Some(Arc::new(std::sync::RwLock::new(token_state)));
        client.instance_url = Some("https://test.salesforce.com".to_string());
        client.tenant_id = Some("test_tenant".to_string());

        client
    }

    #[test]
    fn test_base_url_construction() {
        let auth_client = create_mock_auth_client();
        let bulk_client = ClientBuilder::new(auth_client).build();

        let base_url = bulk_client.base_url().unwrap();
        assert_eq!(
            base_url,
            format!(
                "https://test.salesforce.com/services/data/v{}",
                crate::DEFAULT_API_VERSION
            )
        );
    }

    #[test]
    fn test_base_url_with_different_versions() {
        let auth_client = create_mock_auth_client();

        let bulk_client_default = ClientBuilder::new(auth_client.clone()).build();
        assert_eq!(
            bulk_client_default.base_url().unwrap(),
            format!(
                "https://test.salesforce.com/services/data/v{}",
                crate::DEFAULT_API_VERSION
            )
        );

        let bulk_client_59 = ClientBuilder::new(auth_client).api_version("59.0").build();
        assert_eq!(
            bulk_client_59.base_url().unwrap(),
            "https://test.salesforce.com/services/data/v59.0"
        );
    }

    #[test]
    fn test_base_url_without_instance_url() {
        let mut client = client::Builder::new()
            .credentials(client::Credentials {
                client_id: "test_client_id".to_string(),
                client_secret: Some("test_secret".to_string()),
                username: None,
                password: None,
                instance_url: "https://test.salesforce.com".to_string(),
                tenant_id: "test_tenant".to_string(),
            })
            .build()
            .unwrap();

        // Manually clear instance_url to simulate unconnected state
        client.instance_url = None;

        let bulk_client = ClientBuilder::new(client).api_version("58.0").build();
        let result = bulk_client.base_url();

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), client::Error::NotConnected));
    }
}
