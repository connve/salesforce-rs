//! Tooling API client wrapper.

use crate::client;
use std::sync::Arc;
use std::time::Duration;

use crate::{DEFAULT_API_VERSION, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_REQUEST_TIMEOUT_SECS};

use super::{CreateManagedEventSubscriptionRequest, CreateManagedEventSubscriptionResponse};

/// Error type for Tooling API operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication or client error from salesforce-core.
    #[error("Authentication error: {source}")]
    Auth {
        #[source]
        source: client::Error,
    },

    /// Network-level communication failure.
    ///
    /// Covers connection refused, timeouts, TLS errors, HTTP client construction
    /// failures, and errors reading the response body.
    #[error("Communication error: {source}")]
    Communication {
        #[source]
        source: reqwest::Error,
    },

    /// Serialization or deserialization error for JSON data.
    #[error("Serialization error: {source}")]
    Serialization {
        #[source]
        source: serde_json::Error,
    },

    /// Salesforce API returned an error response.
    #[error("Tooling API error: {message} (status: {status})")]
    ApiError { status: u16, message: String },

    /// Instance URL not available.
    ///
    /// This error occurs when the auth client was not connected before use.
    #[error("Instance URL not available: call connect() on the auth client first")]
    MissingInstanceUrl,

    /// Failed to build the client.
    ///
    /// This variant is reserved for future validation errors.
    #[error("Failed to build Tooling API client")]
    Build,
}

/// Client for Salesforce Tooling API operations.
///
/// This client wraps the authenticated Salesforce client and provides
/// methods for working with metadata objects and development tools.
#[derive(Clone, Debug)]
pub struct Client {
    auth_client: Arc<client::Client>,
    api_version: String,
    connect_timeout: Duration,
    request_timeout: Duration,
}

/// Builder for creating a Tooling API client.
pub struct ClientBuilder {
    auth_client: client::Client,
    api_version: Option<String>,
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
}

impl ClientBuilder {
    /// Creates a new Tooling API client builder.
    ///
    /// # Arguments
    ///
    /// * `auth_client` - An authenticated Salesforce client
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::toolingapi;
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
    /// let tooling_client = toolingapi::ClientBuilder::new(auth_client).build()?;
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

    /// Builds the Tooling API client.
    ///
    /// # Errors
    ///
    /// Currently this method is infallible and always returns `Ok`, but returns
    /// a `Result` for future compatibility if validation is added.
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

    /// Returns the configured connection timeout.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Returns the configured request timeout.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Returns the base URL for Tooling API requests.
    ///
    /// This constructs the URL in the format:
    /// `https://<instance>.salesforce.com/services/data/v<version>/tooling`
    fn base_url(&self) -> Result<String, Error> {
        let instance_url = self
            .auth_client
            .instance_url
            .as_ref()
            .ok_or(Error::MissingInstanceUrl)?;

        Ok(format!(
            "{}/services/data/v{}/tooling",
            instance_url, self.api_version
        ))
    }

    /// Helper to build an HTTP client with authentication headers and connection pooling.
    async fn build_http_client(&self) -> Result<reqwest::Client, Error> {
        crate::http::get_http_client(
            self.auth_client().as_ref(),
            self.connect_timeout(),
            self.request_timeout(),
        )
        .await
        .map_err(|e| match e {
            crate::http::Error::Auth { source } => Error::Auth { source },
            crate::http::Error::InvalidHeader => Error::Auth {
                source: client::Error::LockError,
            },
            crate::http::Error::Build { source } => Error::Communication { source },
        })
    }

    /// Creates a managed event subscription.
    ///
    /// This method sends a POST request to the Tooling API to create a
    /// ManagedEventSubscription metadata record. The subscription allows
    /// you to subscribe to platform events or change data capture events
    /// using the Pub/Sub API's `managed_subscribe()` method.
    ///
    /// # Arguments
    ///
    /// * `request` - The managed event subscription configuration
    ///
    /// # Returns
    ///
    /// Response containing the ID of the created subscription.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::toolingapi::{self, ManagedEventSubscriptionMetadata, ReplayPreset, SubscriptionState};
    ///
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
    /// let tooling_client = toolingapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let subscription = toolingapi::CreateManagedEventSubscriptionRequest {
    ///     full_name: "Managed_Sub_OpportunityChangeEvent".to_string(),
    ///     metadata: ManagedEventSubscriptionMetadata {
    ///         label: "Managed Sub OpportunityChangeEvent".to_string(),
    ///         topic_name: "/data/OpportunityChangeEvent".to_string(),
    ///         default_replay: ReplayPreset::Latest,
    ///         state: SubscriptionState::Run,
    ///         error_recovery_replay: ReplayPreset::Latest,
    ///     },
    /// };
    ///
    /// let response = tooling_client.create_managed_event_subscription(subscription).await?;
    /// println!("Created subscription with ID: {}", response.id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_managed_event_subscription(
        &self,
        request: CreateManagedEventSubscriptionRequest,
    ) -> Result<CreateManagedEventSubscriptionResponse, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.base_url()?;
        let url = format!("{base_url}/sobjects/ManagedEventSubscription");

        let response = http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|source| Error::Communication { source })?;

        let status = response.status();

        if status.is_success() {
            response
                .json::<CreateManagedEventSubscriptionResponse>()
                .await
                .map_err(|source| Error::Communication { source })
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(Error::ApiError {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }
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

    #[tokio::test]
    async fn test_reqwest_error_conversion() {
        let reqwest_error = reqwest::Client::new()
            .get("http://invalid-url-that-does-not-exist.test")
            .send()
            .await
            .unwrap_err();

        let error = Error::Communication {
            source: reqwest_error,
        };

        assert!(matches!(error, Error::Communication { .. }));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn test_serde_error_conversion() {
        let bad_json = "{ invalid json }";
        let serde_error: serde_json::Error =
            serde_json::from_str::<serde_json::Value>(bad_json).unwrap_err();

        let error = Error::Serialization {
            source: serde_error,
        };

        assert!(matches!(error, Error::Serialization { .. }));
        assert!(std::error::Error::source(&error).is_some());
    }
}
