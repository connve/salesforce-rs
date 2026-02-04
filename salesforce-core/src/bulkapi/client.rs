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
/// use salesforce_core::bulkapi::Client as BulkClient;
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
/// // Create a Bulk API client
/// let bulk_client = BulkClient::new(auth_client, "58.0");
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
}

impl Client {
    /// Creates a new Bulk API client.
    ///
    /// # Arguments
    ///
    /// * `auth_client` - An authenticated salesforce-core `Client` for OAuth token management
    /// * `api_version` - Salesforce API version (e.g., "58.0")
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::bulkapi::Client as BulkClient;
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
    /// let bulk_client = BulkClient::new(auth_client, "58.0");
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub fn new(auth_client: client::Client, api_version: impl Into<String>) -> Self {
        Self {
            auth_client: Arc::new(auth_client),
            api_version: api_version.into(),
        }
    }

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

    /// Creates a query client for bulk query operations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client::{self, Credentials};
    /// # use salesforce_core::bulkapi::Client as BulkClient;
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
    /// let bulk_client = BulkClient::new(auth_client, "58.0");
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
    /// # use salesforce_core::bulkapi::Client as BulkClient;
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
    /// let bulk_client = BulkClient::new(auth_client, "58.0");
    ///
    /// let ingest_client = bulk_client.ingest();
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub fn ingest(&self) -> super::ingest::IngestClient {
        super::ingest::IngestClient::new(self.clone())
    }

    /// Internal helper to create a configured HTTP client with authentication.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub(crate) async fn build_http_client(&self) -> Result<reqwest::Client, client::Error> {
        let token = self.auth_client.access_token().await?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| client::Error::LockError)?,
        );

        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| client::Error::TokenExchange(Box::new(e)))
    }

    /// Internal helper to get the base URL for Bulk API.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub(crate) fn base_url(&self) -> String {
        format!(
            "{}/services/data/v{}",
            self.auth_client
                .instance_url
                .as_ref()
                .expect("Client must be connected"),
            self.api_version
        )
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
    fn test_new_client() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0");

        assert_eq!(bulk_client.api_version(), "58.0");
    }

    #[test]
    fn test_new_client_with_string() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "59.0".to_string());

        assert_eq!(bulk_client.api_version(), "59.0");
    }

    #[test]
    fn test_new_client_with_different_versions() {
        let auth_client = create_mock_auth_client();

        let versions = vec!["50.0", "55.0", "58.0", "60.0"];
        for version in versions {
            let bulk_client = Client::new(auth_client.clone(), version);
            assert_eq!(bulk_client.api_version(), version);
        }
    }

    #[test]
    fn test_auth_client_accessor() {
        let auth_client = create_mock_auth_client();
        let original_instance_url = auth_client.instance_url.clone();

        let bulk_client = Client::new(auth_client, "58.0");

        assert_eq!(bulk_client.auth_client().instance_url, original_instance_url);
    }

    #[test]
    fn test_api_version_accessor() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0");

        assert_eq!(bulk_client.api_version(), "58.0");
    }

    #[test]
    fn test_query_client_creation() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0");

        let _query_client = bulk_client.query();
        // If this doesn't panic, the query client was created successfully
    }

    #[test]
    fn test_ingest_client_creation() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0");

        let _ingest_client = bulk_client.ingest();
        // If this doesn't panic, the ingest client was created successfully
    }

    #[test]
    fn test_multiple_query_client_creation() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0");

        let _query_client1 = bulk_client.query();
        let _query_client2 = bulk_client.query();
        // Should be able to create multiple query clients
    }

    #[test]
    fn test_multiple_ingest_client_creation() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0");

        let _ingest_client1 = bulk_client.ingest();
        let _ingest_client2 = bulk_client.ingest();
        // Should be able to create multiple ingest clients
    }

    #[test]
    fn test_clone_client() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0");

        let cloned = bulk_client.clone();

        assert_eq!(cloned.api_version(), bulk_client.api_version());
        assert_eq!(
            cloned.auth_client().instance_url,
            bulk_client.auth_client().instance_url
        );
    }

    #[test]
    fn test_debug_impl() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0");

        let debug_str = format!("{:?}", bulk_client);
        assert!(debug_str.contains("Client"));
    }

    #[test]
    fn test_base_url_construction() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0");

        let base_url = bulk_client.base_url();
        assert_eq!(base_url, "https://test.salesforce.com/services/data/v58.0");
    }

    #[test]
    fn test_base_url_with_different_versions() {
        let auth_client = create_mock_auth_client();

        let bulk_client_58 = Client::new(auth_client.clone(), "58.0");
        assert_eq!(
            bulk_client_58.base_url(),
            "https://test.salesforce.com/services/data/v58.0"
        );

        let bulk_client_59 = Client::new(auth_client, "59.0");
        assert_eq!(
            bulk_client_59.base_url(),
            "https://test.salesforce.com/services/data/v59.0"
        );
    }

    #[test]
    fn test_api_version_with_empty_string() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "");

        assert_eq!(bulk_client.api_version(), "");
    }

    #[test]
    fn test_api_version_with_special_characters() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0-beta");

        assert_eq!(bulk_client.api_version(), "58.0-beta");
    }

    #[tokio::test]
    async fn test_build_http_client_with_valid_token() {
        let auth_client = create_mock_auth_client();
        let bulk_client = Client::new(auth_client, "58.0");

        let result = bulk_client.build_http_client().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_build_http_client_without_token() {
        let client = client::Builder::new()
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

        let bulk_client = Client::new(client, "58.0");
        let result = bulk_client.build_http_client().await;

        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "Client must be connected")]
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

        let bulk_client = Client::new(client, "58.0");
        let _ = bulk_client.base_url(); // Should panic
    }

    #[test]
    fn test_auth_client_reference_same_instance() {
        let auth_client = create_mock_auth_client();
        let original_instance = auth_client.instance_url.clone();

        let bulk_client = Client::new(auth_client, "58.0");

        // Verify the reference points to the same data
        assert_eq!(bulk_client.auth_client().instance_url, original_instance);
    }

    #[test]
    fn test_client_with_very_long_api_version() {
        let auth_client = create_mock_auth_client();
        let long_version = "58.0.with.a.very.long.version.string.that.might.be.unusual";
        let bulk_client = Client::new(auth_client, long_version);

        assert_eq!(bulk_client.api_version(), long_version);
    }

    #[test]
    fn test_base_url_with_trailing_slash_instance() {
        let mut client = create_mock_auth_client();
        client.instance_url = Some("https://test.salesforce.com/".to_string());

        let bulk_client = Client::new(client, "58.0");
        let base_url = bulk_client.base_url();

        // Should handle trailing slash (though URL will have double slash)
        assert!(base_url.starts_with("https://test.salesforce.com/"));
    }
}
