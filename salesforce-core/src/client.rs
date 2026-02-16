use oauth2::basic::BasicTokenType;
use oauth2::{EmptyExtraTokenFields, RefreshToken, TokenResponse};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default OAuth2 token endpoint path.
const DEFAULT_TOKEN_PATH: &str = "/services/oauth2/token";

/// Buffer time (in seconds) before token expiry to trigger refresh.
/// Refresh tokens 5 minutes before they expire to avoid race conditions.
const DEFAULT_TOKEN_REFRESH_BUFFER_SECONDS: u64 = 300;

/// Errors that can occur during client operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Failed to read credentials file from disk.
    #[error("Failed to read credentials file at {path}: {source}")]
    ReadCredentials {
        /// Path to the credentials file that failed to read.
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Failed to parse credentials JSON.
    #[error("Failed to parse credentials JSON: {source}")]
    ParseCredentials {
        #[source]
        source: serde_json::Error,
    },
    /// Invalid URL format in credentials.
    #[error("Invalid URL format: {source}")]
    ParseUrl {
        #[source]
        source: url::ParseError,
    },
    /// OAuth2 token exchange failed during authentication.
    #[error("OAuth2 token exchange failed: {source}")]
    TokenExchange {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// HTTP request failed during OAuth2 token exchange.
    #[error("OAuth2 request failed with status {status}: {body}")]
    OAuth2RequestFailed { status: u16, body: String },
    /// Required builder parameter was not provided.
    #[error("Missing required attribute: {attribute}")]
    MissingRequiredAttribute { attribute: String },
    /// Client secret is required for this authentication flow.
    #[error("Client secret is required for authentication")]
    MissingClientSecret,
    /// Username is required for username-password flow.
    #[error("Username is required for username-password authentication")]
    MissingUsername,
    /// Password is required for username-password flow.
    #[error("Password is required for username-password authentication")]
    MissingPassword,
    /// Failed to get current system time.
    #[error("Failed to get current system time: {source}")]
    SystemTimeError {
        #[source]
        source: std::time::SystemTimeError,
    },
    /// Token expiry time calculation resulted in arithmetic overflow.
    #[error("Token expiry time calculation overflow")]
    TokenExpiryOverflow,
    /// Time threshold calculation resulted in arithmetic overflow.
    #[error("Time threshold calculation overflow")]
    TimeThresholdOverflow,
    /// Token refresh is not available (no refresh token present).
    #[error("Token refresh not available: no refresh token in response")]
    NoRefreshToken,
    /// Failed to acquire lock on token state.
    #[error("Failed to acquire lock on token state")]
    LockError,
    /// Client is not connected - call connect() before using.
    #[error(
        "Client is not connected. Call connect() first to authenticate and retrieve instance URL."
    )]
    NotConnected,
    /// Failed to build HTTP client.
    #[error("Failed to build HTTP client: {source}")]
    HttpClientBuild {
        #[source]
        source: reqwest::Error,
    },
}

/// Type alias for Salesforce OAuth2 token response using standard fields.
pub type SalesforceTokenResponse =
    oauth2::StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>;

/// Internal state for managing token lifecycle.
#[derive(Debug, Clone)]
pub(crate) struct TokenState {
    /// The current access token response.
    token_response: SalesforceTokenResponse,
    /// Unix timestamp (seconds) when the token expires.
    expires_at: u64,
}

impl TokenState {
    /// Creates a new token state from a token response.
    pub(crate) fn new(token_response: SalesforceTokenResponse) -> Result<Self, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|source| Error::SystemTimeError { source })?
            .as_secs();

        let expires_at = if let Some(expires_in) = token_response.expires_in() {
            now.checked_add(expires_in.as_secs())
                .ok_or(Error::TokenExpiryOverflow)?
        } else {
            // Default to 2 hours if not provided (Salesforce default)
            now.checked_add(7200).ok_or(Error::TokenExpiryOverflow)?
        };

        Ok(Self {
            token_response,
            expires_at,
        })
    }

    /// Returns true if the token is expired or will expire within the buffer time.
    fn is_expired(&self, buffer_seconds: u64) -> Result<bool, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|source| Error::SystemTimeError { source })?
            .as_secs();

        let threshold = now
            .checked_add(buffer_seconds)
            .ok_or(Error::TimeThresholdOverflow)?;

        Ok(threshold >= self.expires_at)
    }

    /// Returns the access token as a string.
    fn access_token(&self) -> &str {
        self.token_response.access_token().secret()
    }

    /// Returns the refresh token if available.
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.token_response.refresh_token()
    }
}

/// OAuth2 authentication flow type.
///
/// Salesforce supports multiple OAuth2 flows for different use cases.
/// Choose the appropriate flow based on your application's requirements.
///
/// # Flow Descriptions
///
/// ## Client Credentials
///
/// The Client Credentials flow is used for server-to-server API integration
/// where the application acts on its own behalf rather than on behalf of a user.
/// This is the default flow if not specified.
///
/// **Use when:** Your application needs to access Salesforce APIs without user interaction.
///
/// **Required credentials:**
/// - `client_id`
/// - `client_secret`
///
/// ## Username-Password
///
/// The Resource Owner Password Credentials flow allows authentication using
/// a username and password. This flow should only be used when there is a high
/// degree of trust between the user and the application.
///
/// **Use when:** You need to authenticate as a specific user programmatically.
///
/// **Required credentials:**
/// - `client_id`
/// - `client_secret`
/// - `username`
/// - `password`
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthFlow {
    /// OAuth2 Client Credentials flow for server-to-server authentication.
    ///
    /// Requires: `client_id`, `client_secret`
    #[default]
    ClientCredentials,
    /// OAuth2 Resource Owner Password Credentials flow for user authentication.
    ///
    /// Requires: `client_id`, `client_secret`, `username`, `password`
    UsernamePassword,
}

/// Salesforce OAuth2 credentials.
///
/// Obtained from a Salesforce Connected App. Different fields are required
/// depending on the [`AuthFlow`] used.
///
/// # Creating a Connected App
///
/// 1. In Salesforce Setup, navigate to App Manager
/// 2. Create a new Connected App
/// 3. Enable OAuth Settings
/// 4. Set the callback URL and select OAuth scopes
/// 5. Copy the Consumer Key (client_id) and Consumer Secret (client_secret)
///
/// # Examples
///
/// ## Client Credentials
///
/// ```
/// use salesforce_core::client::Credentials;
///
/// let creds = Credentials {
///     client_id: "your_client_id".to_string(),
///     client_secret: Some("your_client_secret".to_string()),
///     username: None,
///     password: None,
///     instance_url: "https://your-instance.salesforce.com".to_string(),
///     tenant_id: "your_tenant_id".to_string(),
/// };
/// ```
///
/// ## Username-Password
///
/// ```
/// use salesforce_core::client::Credentials;
///
/// let creds = Credentials {
///     client_id: "your_client_id".to_string(),
///     client_secret: Some("your_client_secret".to_string()),
///     username: Some("user@example.com".to_string()),
///     password: Some("your_password".to_string()),
///     instance_url: "https://your-instance.salesforce.com".to_string(),
///     tenant_id: "your_tenant_id".to_string(),
/// };
/// ```
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credentials {
    /// Client ID from the Connected App (Consumer Key).
    pub client_id: String,
    /// Client Secret from the Connected App (Consumer Secret).
    ///
    /// Required for: [`AuthFlow::ClientCredentials`], [`AuthFlow::UsernamePassword`]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Username for authentication (email address).
    ///
    /// Required for: [`AuthFlow::UsernamePassword`]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password for authentication.
    ///
    /// Required for: [`AuthFlow::UsernamePassword`]
    ///
    /// **Note:** If your org requires a security token, append it to the password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Salesforce instance URL (e.g., `https://mydomain.salesforce.com`).
    ///
    /// For production orgs, use `https://login.salesforce.com`.
    /// For sandbox orgs, use `https://test.salesforce.com`.
    pub instance_url: String,
    /// Organization ID (15 or 18 character Salesforce Org ID).
    pub tenant_id: String,
}

/// Source for loading credentials.
#[derive(Debug, Clone)]
pub enum CredentialsFrom {
    /// Load credentials from a JSON file.
    Path(PathBuf),
    /// Use credentials provided directly.
    Value(Credentials),
}

/// OAuth2 client for Salesforce API authentication.
///
/// Use [`Builder`] to construct a client instance. The client supports multiple
/// OAuth2 authentication flows via the [`AuthFlow`] enum.
///
/// # Examples
///
/// ## Client Credentials Flow (Default)
///
/// ```no_run
/// use salesforce_core::client::{self, Credentials, AuthFlow};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = client::Builder::new()
///     .credentials(Credentials {
///         client_id: "your_client_id".to_string(),
///         client_secret: Some("your_client_secret".to_string()),
///         username: None,
///         password: None,
///         instance_url: "https://your-instance.salesforce.com".to_string(),
///         tenant_id: "your_tenant_id".to_string(),
///     })
///     // .auth_flow(AuthFlow::ClientCredentials) // Optional, this is the default
///     .build()?
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Username-Password Flow
///
/// ```no_run
/// use salesforce_core::client::{self, Credentials, AuthFlow};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = client::Builder::new()
///     .credentials(Credentials {
///         client_id: "your_client_id".to_string(),
///         client_secret: Some("your_client_secret".to_string()),
///         username: Some("user@example.com".to_string()),
///         password: Some("your_password".to_string()),
///         instance_url: "https://your-instance.salesforce.com".to_string(),
///         tenant_id: "your_tenant_id".to_string(),
///     })
///     .auth_flow(AuthFlow::UsernamePassword)
///     .build()?
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Loading Credentials from File
///
/// ```no_run
/// use salesforce_core::client;
/// use std::path::PathBuf;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = client::Builder::new()
///     .credentials_path(PathBuf::from("credentials.json"))
///     .build()?
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[allow(clippy::type_complexity)]
pub struct Client {
    /// Source of credentials (file path or direct value).
    credentials_from: CredentialsFrom,
    /// OAuth2 authentication flow to use.
    auth_flow: AuthFlow,
    /// Thread-safe token state with automatic refresh capabilities.
    pub(crate) token_state: Option<Arc<RwLock<TokenState>>>,
    /// Salesforce instance URL.
    pub instance_url: Option<String>,
    /// Organization ID.
    pub tenant_id: Option<String>,
}

impl Client {
    /// Validates that required credential fields are present for the selected auth flow.
    fn validate_credentials(&self, credentials: &Credentials) -> Result<(), Error> {
        match self.auth_flow {
            AuthFlow::ClientCredentials => {
                credentials
                    .client_secret
                    .as_ref()
                    .ok_or(Error::MissingClientSecret)?;
            }
            AuthFlow::UsernamePassword => {
                credentials
                    .client_secret
                    .as_ref()
                    .ok_or(Error::MissingClientSecret)?;
                credentials
                    .username
                    .as_ref()
                    .ok_or(Error::MissingUsername)?;
                credentials
                    .password
                    .as_ref()
                    .ok_or(Error::MissingPassword)?;
            }
        }

        Ok(())
    }

    /// Connects to Salesforce and exchanges credentials for an access token.
    ///
    /// This method performs the configured OAuth2 flow to obtain
    /// an access token for API authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Credentials file cannot be read ([`Error::ReadCredentials`])
    /// - Credentials JSON is invalid ([`Error::ParseCredentials`])
    /// - Required fields are missing for the auth flow ([`Error::InvalidCredentials`])
    /// - Instance URL is malformed ([`Error::ParseUrl`])
    /// - OAuth2 token exchange fails ([`Error::TokenExchange`])
    pub async fn connect(mut self) -> Result<Self, Error> {
        let credentials = match &self.credentials_from {
            CredentialsFrom::Value(creds) => creds.clone(),
            CredentialsFrom::Path(path) => {
                let credentials_string =
                    fs::read_to_string(path).map_err(|e| Error::ReadCredentials {
                        path: path.clone(),
                        source: e,
                    })?;
                serde_json::from_str(&credentials_string)
                    .map_err(|e| Error::ParseCredentials { source: e })?
            }
        };

        // Validate credentials for the selected auth flow
        self.validate_credentials(&credentials)?;

        // Create HTTP client for async requests
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(
                crate::DEFAULT_AUTH_CONNECT_TIMEOUT_SECS,
            ))
            .timeout(std::time::Duration::from_secs(
                crate::DEFAULT_AUTH_REQUEST_TIMEOUT_SECS,
            ))
            .build()
            .map_err(|e| Error::TokenExchange {
                source: Box::new(e),
            })?;

        let token_response = match self.auth_flow {
            AuthFlow::ClientCredentials => {
                self.exchange_client_credentials(&credentials, &http_client)
                    .await?
            }
            AuthFlow::UsernamePassword => {
                self.exchange_password(&credentials, &http_client).await?
            }
        };

        let token_state = TokenState::new(token_response)?;
        self.token_state = Some(Arc::new(RwLock::new(token_state)));
        self.instance_url = Some(credentials.instance_url);
        self.tenant_id = Some(credentials.tenant_id);

        Ok(self)
    }

    /// Performs OAuth2 Client Credentials flow.
    async fn exchange_client_credentials(
        &self,
        credentials: &Credentials,
        http_client: &reqwest::Client,
    ) -> Result<SalesforceTokenResponse, Error> {
        let client_secret = credentials
            .client_secret
            .as_ref()
            .ok_or(Error::MissingClientSecret)?;

        let token_url = format!("{}{}", credentials.instance_url, DEFAULT_TOKEN_PATH);

        let response = http_client
            .post(&token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &credentials.client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .map_err(|e| Error::TokenExchange {
                source: Box::new(e),
            })?;

        let status = response.status();
        let body = response.text().await.map_err(|e| Error::TokenExchange {
            source: Box::new(e),
        })?;

        if !status.is_success() {
            return Err(Error::OAuth2RequestFailed {
                status: status.as_u16(),
                body,
            });
        }

        serde_json::from_str(&body).map_err(|e| Error::TokenExchange {
            source: Box::new(e),
        })
    }

    /// Performs OAuth2 Resource Owner Password Credentials flow.
    async fn exchange_password(
        &self,
        credentials: &Credentials,
        http_client: &reqwest::Client,
    ) -> Result<SalesforceTokenResponse, Error> {
        let client_secret = credentials
            .client_secret
            .as_ref()
            .ok_or(Error::MissingClientSecret)?;
        let username = credentials
            .username
            .as_ref()
            .ok_or(Error::MissingUsername)?;
        let password = credentials
            .password
            .as_ref()
            .ok_or(Error::MissingPassword)?;

        let token_url = format!("{}{}", credentials.instance_url, DEFAULT_TOKEN_PATH);

        let response = http_client
            .post(&token_url)
            .form(&[
                ("grant_type", "password"),
                ("client_id", &credentials.client_id),
                ("client_secret", client_secret),
                ("username", username),
                ("password", password),
            ])
            .send()
            .await
            .map_err(|e| Error::TokenExchange {
                source: Box::new(e),
            })?;

        let status = response.status();
        let body = response.text().await.map_err(|e| Error::TokenExchange {
            source: Box::new(e),
        })?;

        if !status.is_success() {
            return Err(Error::OAuth2RequestFailed {
                status: status.as_u16(),
                body,
            });
        }

        serde_json::from_str(&body).map_err(|e| Error::TokenExchange {
            source: Box::new(e),
        })
    }

    /// Refreshes the access token using the refresh token.
    ///
    /// This method is called automatically by [`access_token`](Self::access_token)
    /// when the token is expired or about to expire.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No refresh token is available ([`Error::NoRefreshToken`])
    /// - Token refresh fails ([`Error::TokenExchange`])
    /// - Failed to acquire token state lock ([`Error::LockError`])
    async fn refresh_token(&self) -> Result<(), Error> {
        let token_state_arc = self.token_state.as_ref().ok_or(Error::NoRefreshToken)?;

        // Read lock to get refresh token
        let refresh_token = {
            let state = token_state_arc.read().map_err(|_| Error::LockError)?;

            state.refresh_token().ok_or(Error::NoRefreshToken)?.clone()
        };

        // Load credentials for OAuth2 client setup
        let credentials = match &self.credentials_from {
            CredentialsFrom::Value(creds) => creds.clone(),
            CredentialsFrom::Path(path) => {
                let credentials_string =
                    fs::read_to_string(path).map_err(|e| Error::ReadCredentials {
                        path: path.clone(),
                        source: e,
                    })?;
                serde_json::from_str(&credentials_string)
                    .map_err(|e| Error::ParseCredentials { source: e })?
            }
        };

        let client_secret = credentials
            .client_secret
            .as_ref()
            .ok_or(Error::MissingClientSecret)?;

        let token_url = format!("{}{}", credentials.instance_url, DEFAULT_TOKEN_PATH);

        // Create HTTP client
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(
                crate::DEFAULT_AUTH_CONNECT_TIMEOUT_SECS,
            ))
            .timeout(std::time::Duration::from_secs(
                crate::DEFAULT_AUTH_REQUEST_TIMEOUT_SECS,
            ))
            .build()
            .map_err(|e| Error::TokenExchange {
                source: Box::new(e),
            })?;

        // Exchange refresh token for new access token
        let response = http_client
            .post(&token_url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", &credentials.client_id),
                ("client_secret", client_secret),
                ("refresh_token", refresh_token.secret()),
            ])
            .send()
            .await
            .map_err(|e| Error::TokenExchange {
                source: Box::new(e),
            })?;

        let status = response.status();
        let body = response.text().await.map_err(|e| Error::TokenExchange {
            source: Box::new(e),
        })?;

        if !status.is_success() {
            return Err(Error::OAuth2RequestFailed {
                status: status.as_u16(),
                body,
            });
        }

        let new_token_response: SalesforceTokenResponse =
            serde_json::from_str(&body).map_err(|e| Error::TokenExchange {
                source: Box::new(e),
            })?;

        // Update token state with write lock
        let new_state = TokenState::new(new_token_response)?;
        let mut state = token_state_arc.write().map_err(|_| Error::LockError)?;
        *state = new_state;

        Ok(())
    }

    /// Returns the current access token without refreshing.
    ///
    /// This is a synchronous method that returns the current token state.
    /// Use [`access_token`](Self::access_token) for automatic refresh.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Client is not connected ([`Error::NoRefreshToken`])
    /// - Failed to acquire token state lock ([`Error::LockError`])
    pub fn current_access_token(&self) -> Result<String, Error> {
        let token_state_arc = self.token_state.as_ref().ok_or(Error::NoRefreshToken)?;

        let state = token_state_arc.read().map_err(|_| Error::LockError)?;

        Ok(state.access_token().to_string())
    }

    /// Forces a new token by reconnecting to Salesforce.
    ///
    /// This method performs a fresh OAuth2 authentication regardless of whether
    /// the current token is expired. Use this when you receive INVALID_SESSION_ID
    /// errors from Salesforce, which indicate the session was revoked due to:
    /// - IP address restrictions
    /// - Session security policy changes
    /// - Manual session termination
    /// - Other security-related invalidation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Client is not connected ([`Error::NoRefreshToken`])
    /// - OAuth2 authentication fails ([`Error::TokenExchange`])
    /// - Failed to acquire token state lock ([`Error::LockError`])
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = client::Builder::new()
    ///     .credentials(Credentials {
    ///         client_id: "your_client_id".to_string(),
    ///         client_secret: Some("your_client_secret".to_string()),
    ///         username: None,
    ///         password: None,
    ///         instance_url: "https://your-instance.salesforce.com".to_string(),
    ///         tenant_id: "your_tenant_id".to_string(),
    ///     })
    ///     .build()?
    ///     .connect()
    ///     .await?;
    ///
    /// // Force new session after INVALID_SESSION_ID error
    /// client.reconnect().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn reconnect(&mut self) -> Result<(), Error> {
        // Load credentials
        let credentials = match &self.credentials_from {
            CredentialsFrom::Value(creds) => creds.clone(),
            CredentialsFrom::Path(path) => {
                let credentials_string =
                    fs::read_to_string(path).map_err(|e| Error::ReadCredentials {
                        path: path.clone(),
                        source: e,
                    })?;
                serde_json::from_str(&credentials_string)
                    .map_err(|e| Error::ParseCredentials { source: e })?
            }
        };

        self.validate_credentials(&credentials)?;

        // Create HTTP client
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(
                crate::DEFAULT_AUTH_CONNECT_TIMEOUT_SECS,
            ))
            .timeout(std::time::Duration::from_secs(
                crate::DEFAULT_AUTH_REQUEST_TIMEOUT_SECS,
            ))
            .build()
            .map_err(|e| Error::TokenExchange {
                source: Box::new(e),
            })?;

        // Perform fresh OAuth2 authentication
        let token_response = match self.auth_flow {
            AuthFlow::ClientCredentials => {
                self.exchange_client_credentials(&credentials, &http_client)
                    .await?
            }
            AuthFlow::UsernamePassword => {
                self.exchange_password(&credentials, &http_client).await?
            }
        };

        // Update token state
        let token_state = TokenState::new(token_response)?;
        self.token_state = Some(Arc::new(RwLock::new(token_state)));

        Ok(())
    }

    /// Returns a valid access token, automatically refreshing if necessary.
    ///
    /// This method checks if the current token is expired or will expire soon
    /// (within 5 minutes). If so, it automatically refreshes the token using
    /// the refresh token before returning.
    ///
    /// Note: This only handles token expiry. For INVALID_SESSION_ID errors
    /// (session revoked), use [`reconnect`](Self::reconnect) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Client is not connected ([`Error::NoRefreshToken`])
    /// - Token refresh fails when needed ([`Error::TokenExchange`])
    /// - Failed to acquire token state lock ([`Error::LockError`])
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = client::Builder::new()
    ///     .credentials(Credentials {
    ///         client_id: "your_client_id".to_string(),
    ///         client_secret: Some("your_client_secret".to_string()),
    ///         username: None,
    ///         password: None,
    ///         instance_url: "https://your-instance.salesforce.com".to_string(),
    ///         tenant_id: "your_tenant_id".to_string(),
    ///     })
    ///     .build()?
    ///     .connect()
    ///     .await?;
    ///
    /// // Get access token - automatically refreshes if expired
    /// let token = client.access_token().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn access_token(&self) -> Result<String, Error> {
        let token_state_arc = self.token_state.as_ref().ok_or(Error::NoRefreshToken)?;

        // Check if token needs refresh
        let needs_refresh = {
            let state = token_state_arc.read().map_err(|_| Error::LockError)?;

            state.is_expired(DEFAULT_TOKEN_REFRESH_BUFFER_SECONDS)?
        };

        // Refresh if needed
        if needs_refresh {
            self.refresh_token().await?;
        }

        // Return access token
        let state = token_state_arc.read().map_err(|_| Error::LockError)?;

        Ok(state.access_token().to_string())
    }
}

/// Builder for constructing a [`Client`].
///
/// The builder allows you to configure the authentication flow and credentials
/// source before creating a client instance.
///
/// # Examples
///
/// ## Using Client Credentials Flow
///
/// ```no_run
/// use salesforce_core::client::{self, Credentials, AuthFlow};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = client::Builder::new()
///     .credentials(Credentials {
///         client_id: "your_client_id".to_string(),
///         client_secret: Some("your_client_secret".to_string()),
///         username: None,
///         password: None,
///         instance_url: "https://your-instance.salesforce.com".to_string(),
///         tenant_id: "your_tenant_id".to_string(),
///     })
///     .auth_flow(AuthFlow::ClientCredentials)
///     .build()?
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Using Username-Password Flow
///
/// ```no_run
/// use salesforce_core::client::{self, Credentials, AuthFlow};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = client::Builder::new()
///     .credentials(Credentials {
///         client_id: "your_client_id".to_string(),
///         client_secret: Some("your_client_secret".to_string()),
///         username: Some("user@example.com".to_string()),
///         password: Some("your_password".to_string()),
///         instance_url: "https://your-instance.salesforce.com".to_string(),
///         tenant_id: "your_tenant_id".to_string(),
///     })
///     .auth_flow(AuthFlow::UsernamePassword)
///     .build()?
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Loading from File
///
/// ```no_run
/// use salesforce_core::client;
/// use std::path::PathBuf;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = client::Builder::new()
///     .credentials_path(PathBuf::from("credentials.json"))
///     .build()?
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct Builder {
    credentials_from: Option<CredentialsFrom>,
    auth_flow: Option<AuthFlow>,
}

impl Builder {
    /// Creates a new builder.
    ///
    /// # Returns
    ///
    /// A `Builder` instance for configuring the Salesforce client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets credentials to load from a JSON file.
    ///
    /// The file should contain a JSON object with the required fields for
    /// your chosen authentication flow. For example:
    ///
    /// ```json
    /// {
    ///   "client_id": "your_client_id",
    ///   "client_secret": "your_client_secret",
    ///   "instance_url": "https://your-instance.salesforce.com",
    ///   "tenant_id": "your_tenant_id"
    /// }
    /// ```
    ///
    /// For [`AuthFlow::UsernamePassword`], also include `username` and `password`.
    ///
    /// # Returns
    ///
    /// `Self` for method chaining.
    pub fn credentials_path(mut self, path: PathBuf) -> Self {
        self.credentials_from = Some(CredentialsFrom::Path(path));
        self
    }

    /// Sets credentials directly.
    ///
    /// Provide a [`Credentials`] struct with the appropriate fields populated
    /// for your chosen authentication flow.
    ///
    /// # Returns
    ///
    /// `Self` for method chaining.
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials_from = Some(CredentialsFrom::Value(credentials));
        self
    }

    /// Sets the OAuth2 authentication flow.
    ///
    /// Defaults to [`AuthFlow::ClientCredentials`] if not specified.
    ///
    /// # Available Flows
    ///
    /// - [`AuthFlow::ClientCredentials`] - Server-to-server authentication
    /// - [`AuthFlow::UsernamePassword`] - User authentication with username and password
    ///
    /// # Returns
    ///
    /// `Self` for method chaining.
    pub fn auth_flow(mut self, auth_flow: AuthFlow) -> Self {
        self.auth_flow = Some(auth_flow);
        self
    }

    /// Builds the client.
    ///
    /// # Returns
    ///
    /// A `Result` containing the configured `Client` if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if credentials were not provided via either
    /// [`credentials_path`](Self::credentials_path) or [`credentials`](Self::credentials).
    pub fn build(self) -> Result<Client, Error> {
        Ok(Client {
            credentials_from: self.credentials_from.ok_or_else(|| {
                Error::MissingRequiredAttribute {
                    attribute: "credentials or credentials_path".to_string(),
                }
            })?,
            auth_flow: self.auth_flow.unwrap_or_default(),
            token_state: None,
            instance_url: None,
            tenant_id: None,
        })
    }
}

#[cfg(test)]
mod tests {

    use std::env;

    use super::*;

    #[test]
    fn test_build_without_credentials() {
        let client = Builder::new().build();
        assert!(matches!(
            client,
            Err(Error::MissingRequiredAttribute { attribute }) if attribute == "credentials or credentials_path"
        ));
    }

    #[test]
    fn test_build_with_credentials() {
        let mut path = env::temp_dir();
        path.push(format!("credentials_{}.json", std::process::id()));
        let client = Builder::new().credentials_path(path).build();
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_connect_with_invalid_credentials() {
        let creds: &str = r#"{"client_id":"client_id"}"#;
        let mut path = env::temp_dir();
        path.push(format!("invalid_credentials_{}.json", std::process::id()));
        let _ = fs::write(path.clone(), creds);
        let client = Builder::new()
            .credentials_path(path.clone())
            .build()
            .unwrap();
        let result = client.connect().await;
        let _ = fs::remove_file(path);
        assert!(matches!(result, Err(Error::ParseCredentials { .. })));
    }

    #[tokio::test]
    async fn test_connect_with_invalid_url() {
        let creds: &str = r#"
            {
                "client_id": "some_client_id",
                "client_secret": "some_client_secret",
                "instance_url": "mydomain.salesforce.com",
                "tenant_id": "some_tenant_id"
            }"#;
        let mut path = env::temp_dir();
        path.push(format!(
            "invalid_url_credentials_{}.json",
            std::process::id()
        ));
        let _ = fs::write(path.clone(), creds);
        let client = Builder::new()
            .credentials_path(path.clone())
            .build()
            .unwrap();
        let result = client.connect().await;
        let _ = fs::remove_file(path);
        // Invalid URL (missing https://) results in network error wrapped in TokenExchange
        assert!(matches!(result, Err(Error::TokenExchange { .. })));
    }

    #[tokio::test]
    async fn test_connect_with_missing_file() {
        let mut path = env::temp_dir();
        path.push(format!("nonexistent_{}.json", std::process::id()));
        let client = Builder::new().credentials_path(path).build().unwrap();
        let result = client.connect().await;
        assert!(matches!(result, Err(Error::ReadCredentials { .. })));
    }

    #[tokio::test]
    async fn test_connect_with_valid_json_but_invalid_credentials() {
        let creds: &str = r#"
            {
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "instance_url": "https://test.salesforce.com",
                "tenant_id": "test_tenant_id"
            }"#;
        let mut path = env::temp_dir();
        path.push(format!(
            "valid_json_invalid_creds_{}.json",
            std::process::id()
        ));
        let _ = fs::write(path.clone(), creds);
        let client = Builder::new()
            .credentials_path(path.clone())
            .build()
            .unwrap();
        let result = client.connect().await;
        let _ = fs::remove_file(path);
        // Should fail with OAuth2RequestFailed (invalid credentials return HTTP error)
        assert!(matches!(result, Err(Error::OAuth2RequestFailed { .. })));
    }

    #[tokio::test]
    async fn test_connect_with_direct_credentials() {
        let creds = Credentials {
            client_id: "test_client_id".to_string(),
            client_secret: Some("test_client_secret".to_string()),
            username: None,
            password: None,
            instance_url: "https://test.salesforce.com".to_string(),
            tenant_id: "test_tenant_id".to_string(),
        };
        let client = Builder::new().credentials(creds).build().unwrap();
        let result = client.connect().await;
        // Should fail with OAuth2RequestFailed (invalid credentials return HTTP error)
        assert!(matches!(result, Err(Error::OAuth2RequestFailed { .. })));
    }

    #[tokio::test]
    async fn test_client_credentials_flow_missing_secret() {
        let creds = Credentials {
            client_id: "test_client_id".to_string(),
            client_secret: None,
            username: None,
            password: None,
            instance_url: "https://test.salesforce.com".to_string(),
            tenant_id: "test_tenant_id".to_string(),
        };
        let client = Builder::new()
            .credentials(creds)
            .auth_flow(AuthFlow::ClientCredentials)
            .build()
            .unwrap();
        let result = client.connect().await;
        assert!(matches!(result, Err(Error::MissingClientSecret)));
    }

    #[tokio::test]
    async fn test_username_password_flow_missing_username() {
        let creds = Credentials {
            client_id: "test_client_id".to_string(),
            client_secret: Some("test_secret".to_string()),
            username: None,
            password: Some("test_password".to_string()),
            instance_url: "https://test.salesforce.com".to_string(),
            tenant_id: "test_tenant_id".to_string(),
        };
        let client = Builder::new()
            .credentials(creds)
            .auth_flow(AuthFlow::UsernamePassword)
            .build()
            .unwrap();
        let result = client.connect().await;
        assert!(matches!(result, Err(Error::MissingUsername)));
    }

    #[tokio::test]
    async fn test_username_password_flow_missing_password() {
        let creds = Credentials {
            client_id: "test_client_id".to_string(),
            client_secret: Some("test_secret".to_string()),
            username: Some("test_user".to_string()),
            password: None,
            instance_url: "https://test.salesforce.com".to_string(),
            tenant_id: "test_tenant_id".to_string(),
        };
        let client = Builder::new()
            .credentials(creds)
            .auth_flow(AuthFlow::UsernamePassword)
            .build()
            .unwrap();
        let result = client.connect().await;
        assert!(matches!(result, Err(Error::MissingPassword)));
    }

    #[tokio::test]
    async fn test_username_password_flow_with_valid_fields() {
        let creds = Credentials {
            client_id: "test_client_id".to_string(),
            client_secret: Some("test_secret".to_string()),
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            instance_url: "https://test.salesforce.com".to_string(),
            tenant_id: "test_tenant_id".to_string(),
        };
        let client = Builder::new()
            .credentials(creds)
            .auth_flow(AuthFlow::UsernamePassword)
            .build()
            .unwrap();
        let result = client.connect().await;
        // Should fail with OAuth2RequestFailed (invalid credentials return HTTP error, but validation passed)
        assert!(matches!(result, Err(Error::OAuth2RequestFailed { .. })));
    }

    #[tokio::test]
    async fn test_username_password_flow_missing_client_secret() {
        let creds = Credentials {
            client_id: "test_client_id".to_string(),
            client_secret: None,
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            instance_url: "https://test.salesforce.com".to_string(),
            tenant_id: "test_tenant_id".to_string(),
        };
        let client = Builder::new()
            .credentials(creds)
            .auth_flow(AuthFlow::UsernamePassword)
            .build()
            .unwrap();
        let result = client.connect().await;
        assert!(matches!(result, Err(Error::MissingClientSecret)));
    }

    #[test]
    fn test_token_state_expiry_check_with_buffer() {
        use oauth2::basic::BasicTokenResponse;
        use oauth2::AccessToken;
        use std::time::Duration;

        let mut token_response = BasicTokenResponse::new(
            AccessToken::new("test_token".to_string()),
            oauth2::basic::BasicTokenType::Bearer,
            EmptyExtraTokenFields {},
        );
        // Set token to expire in 1 second
        token_response.set_expires_in(Some(&Duration::from_secs(1)));

        let token_state = TokenState::new(token_response).unwrap();

        // Check with 5 minute buffer - should be expired
        let is_expired = token_state.is_expired(300);
        assert!(is_expired.is_ok());
        assert!(is_expired.unwrap());

        // Check with 0 buffer - should not be expired yet
        let is_expired = token_state.is_expired(0);
        assert!(is_expired.is_ok());
        assert!(!is_expired.unwrap());
    }

    #[test]
    fn test_current_access_token_without_connection() {
        let client = Builder::new()
            .credentials(Credentials {
                client_id: "test_id".to_string(),
                client_secret: Some("test_secret".to_string()),
                username: None,
                password: None,
                instance_url: "https://test.salesforce.com".to_string(),
                tenant_id: "test_tenant".to_string(),
            })
            .build()
            .unwrap();

        let result = client.current_access_token();
        assert!(matches!(result, Err(Error::NoRefreshToken)));
    }

    #[tokio::test]
    async fn test_access_token_without_connection() {
        let client = Builder::new()
            .credentials(Credentials {
                client_id: "test_id".to_string(),
                client_secret: Some("test_secret".to_string()),
                username: None,
                password: None,
                instance_url: "https://test.salesforce.com".to_string(),
                tenant_id: "test_tenant".to_string(),
            })
            .build()
            .unwrap();

        let result = client.access_token().await;
        assert!(matches!(result, Err(Error::NoRefreshToken)));
    }

    #[tokio::test]
    async fn test_reconnect_without_connection() {
        let mut client = Builder::new()
            .credentials(Credentials {
                client_id: "test_id".to_string(),
                client_secret: Some("test_secret".to_string()),
                username: None,
                password: None,
                instance_url: "https://test.salesforce.com".to_string(),
                tenant_id: "test_tenant".to_string(),
            })
            .build()
            .unwrap();

        // Reconnect should fail with OAuth2RequestFailed since we have invalid credentials
        let result = client.reconnect().await;
        assert!(matches!(result, Err(Error::OAuth2RequestFailed { .. })));
    }
}
