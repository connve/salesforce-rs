use oauth2::basic::BasicTokenType;
use oauth2::{EmptyExtraTokenFields, RefreshToken, TokenResponse};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
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
    /// The instance URL is not a valid absolute URL.
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
    /// Client ID was not provided to the builder.
    #[error("Client ID not provided: call client_id() or credentials() before build()")]
    MissingClientId,
    /// Instance URL was not provided to the builder.
    #[error("Instance URL not provided: call instance_url() or credentials() before build()")]
    MissingInstanceUrl,
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
    /// The access token contains characters that can't be sent in an HTTP
    /// header.
    #[error("Access token is not a valid HTTP header value")]
    InvalidAccessToken,
}

impl Error {
    /// Returns `true` if the error is transient and the operation could
    /// succeed if retried.
    ///
    /// Only `OAuth2RequestFailed` with a 429 or 5xx status, transient
    /// `TokenExchange` failures (connect/timeout reqwest errors), and
    /// `HttpClientBuild` connect/timeout errors are considered retryable.
    /// All other variants are configuration, parsing, or programmer errors
    /// that cannot be fixed by retrying.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::OAuth2RequestFailed { status, .. } => {
                *status == 429 || (500..600).contains(status)
            }
            Error::TokenExchange { source } => source
                .downcast_ref::<reqwest::Error>()
                .is_some_and(|e| e.is_timeout() || e.is_connect()),
            Error::HttpClientBuild { source } => source.is_timeout() || source.is_connect(),
            _ => false,
        }
    }
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
/// Deserializes from JSON, ignoring unknown fields, so an application can
/// load it from wherever it keeps secrets and pass it to
/// [`Builder::credentials`]. The individual [`Builder`] setters cover the
/// same fields.
///
/// # Creating a Connected App
///
/// 1. In Salesforce Setup, navigate to App Manager
/// 2. Create a new Connected App
/// 3. Enable OAuth Settings
/// 4. Set the callback URL and select OAuth scopes
/// 5. Copy the Consumer Key (client_id) and Consumer Secret (client_secret)
///
/// # Example
///
/// ```
/// use salesforce_core::client::Credentials;
///
/// let creds: Credentials = serde_json::from_str(
///     r#"{
///         "client_id": "your_client_id",
///         "client_secret": "your_client_secret",
///         "instance_url": "https://your-instance.my.salesforce.com"
///     }"#,
/// )?;
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct Credentials {
    /// Client ID from the Connected App (Consumer Key).
    pub client_id: String,
    /// Client Secret from the Connected App (Consumer Secret).
    ///
    /// Required for: [`AuthFlow::ClientCredentials`], [`AuthFlow::UsernamePassword`]
    ///
    /// Redacted from `Debug` output and zeroed on drop.
    pub client_secret: Option<SecretString>,
    /// Username for authentication (email address).
    ///
    /// Required for: [`AuthFlow::UsernamePassword`]
    pub username: Option<String>,
    /// Password for authentication.
    ///
    /// Required for: [`AuthFlow::UsernamePassword`]
    ///
    /// **Note:** If your org requires a security token, append it to the password.
    ///
    /// Redacted from `Debug` output and zeroed on drop.
    pub password: Option<SecretString>,
    /// Salesforce instance URL (e.g., `https://mydomain.salesforce.com`).
    ///
    /// For production orgs, use `https://login.salesforce.com`.
    /// For sandbox orgs, use `https://test.salesforce.com`.
    pub instance_url: String,
    /// Organization ID (15 or 18 character Salesforce Org ID).
    ///
    /// Required for: the Pub/Sub API
    pub tenant_id: Option<String>,
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
/// use salesforce_core::client;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = client::Client::builder()
///     .client_id("your_client_id")
///     .client_secret("your_client_secret")
///     .instance_url("https://your-instance.my.salesforce.com")
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
/// use salesforce_core::client::{self, AuthFlow};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = client::Client::builder()
///     .client_id("your_client_id")
///     .client_secret("your_client_secret")
///     .username("user@example.com")
///     .password("your_password")
///     .instance_url("https://your-instance.my.salesforce.com")
///     .auth_flow(AuthFlow::UsernamePassword)
///     .build()?
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Client {
    /// Credentials validated by [`Builder::build`].
    credentials: Credentials,
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
    /// Start a [`Builder`].
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Connects to Salesforce and exchanges credentials for an access token.
    ///
    /// This method performs the configured OAuth2 flow to obtain
    /// an access token for API authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - OAuth2 token exchange fails ([`Error::TokenExchange`], [`Error::OAuth2RequestFailed`])
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn connect(mut self) -> Result<Self, Error> {
        let token_response = self.exchange_credentials().await?;

        let token_state = TokenState::new(token_response)?;
        self.token_state = Some(Arc::new(RwLock::new(token_state)));
        self.instance_url = Some(self.credentials.instance_url.clone());
        self.tenant_id = self.credentials.tenant_id.clone();

        Ok(self)
    }

    /// Runs the configured auth flow against the token endpoint.
    async fn exchange_credentials(&self) -> Result<SalesforceTokenResponse, Error> {
        let http_client = Self::build_auth_http_client()?;
        match self.auth_flow {
            AuthFlow::ClientCredentials => {
                self.exchange_client_credentials(&self.credentials, &http_client)
                    .await
            }
            AuthFlow::UsernamePassword => {
                self.exchange_password(&self.credentials, &http_client)
                    .await
            }
        }
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
            .ok_or(Error::MissingClientSecret)?
            .expose_secret();

        let token_url = format!("{}{}", credentials.instance_url, DEFAULT_TOKEN_PATH);

        let response = http_client
            .post(&token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", credentials.client_id.as_str()),
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
            .ok_or(Error::MissingClientSecret)?
            .expose_secret();
        let username = credentials
            .username
            .as_ref()
            .ok_or(Error::MissingUsername)?;
        let password = credentials
            .password
            .as_ref()
            .ok_or(Error::MissingPassword)?
            .expose_secret();

        let token_url = format!("{}{}", credentials.instance_url, DEFAULT_TOKEN_PATH);

        let response = http_client
            .post(&token_url)
            .form(&[
                ("grant_type", "password"),
                ("client_id", credentials.client_id.as_str()),
                ("client_secret", client_secret),
                ("username", username.as_str()),
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

    /// Builds an HTTP client for OAuth2 requests.
    fn build_auth_http_client() -> Result<reqwest::Client, Error> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(
                crate::DEFAULT_AUTH_CONNECT_TIMEOUT_SECS,
            ))
            .timeout(std::time::Duration::from_secs(
                crate::DEFAULT_AUTH_REQUEST_TIMEOUT_SECS,
            ))
            .build()
            .map_err(|source| Error::HttpClientBuild { source })
    }

    /// Performs a fresh authentication using the configured auth flow and updates token state
    /// in-place. This can be called with `&self` since it only needs a write lock on the
    /// existing `Arc<RwLock<TokenState>>`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Client is not connected ([`Error::NotConnected`])
    /// - OAuth2 authentication fails ([`Error::TokenExchange`])
    /// - Failed to acquire token state lock ([`Error::LockError`])
    async fn reauthenticate(&self) -> Result<(), Error> {
        let token_state_arc = self.token_state.as_ref().ok_or(Error::NotConnected)?;

        let token_response = self.exchange_credentials().await?;

        let new_state = TokenState::new(token_response)?;
        let mut state = token_state_arc.write().map_err(|_| Error::LockError)?;
        *state = new_state;

        Ok(())
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

        let credentials = &self.credentials;

        let client_secret = credentials
            .client_secret
            .as_ref()
            .ok_or(Error::MissingClientSecret)?
            .expose_secret();

        let token_url = format!("{}{}", credentials.instance_url, DEFAULT_TOKEN_PATH);

        let http_client = Self::build_auth_http_client()?;

        // Exchange refresh token for new access token
        let response = http_client
            .post(&token_url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", credentials.client_id.as_str()),
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
    /// The token is redacted from `Debug` output; read it with
    /// [`ExposeSecret::expose_secret`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Client is not connected ([`Error::NotConnected`])
    /// - Failed to acquire token state lock ([`Error::LockError`])
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub fn current_access_token(&self) -> Result<SecretString, Error> {
        let token_state_arc = self.token_state.as_ref().ok_or(Error::NotConnected)?;

        let state = token_state_arc.read().map_err(|_| Error::LockError)?;

        Ok(SecretString::from(state.access_token()))
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
    /// use salesforce_core::client;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = client::Client::builder()
    ///     .client_id("your_client_id")
    ///     .client_secret("your_client_secret")
    ///     .instance_url("https://your-instance.my.salesforce.com")
    ///     .build()?
    ///     .connect()
    ///     .await?;
    ///
    /// // Force new session after INVALID_SESSION_ID error
    /// client.reconnect().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn reconnect(&mut self) -> Result<(), Error> {
        let token_response = self.exchange_credentials().await?;

        let new_token_state = TokenState::new(token_response)?;
        match &self.token_state {
            Some(existing) => {
                let mut guard = existing.write().map_err(|_| Error::LockError)?;
                *guard = new_token_state;
            }
            None => {
                self.token_state = Some(Arc::new(RwLock::new(new_token_state)));
            }
        }

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
    /// The token is redacted from `Debug` output; read it with
    /// [`ExposeSecret::expose_secret`].
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
    /// use salesforce_core::client;
    /// use salesforce_core::secrecy::ExposeSecret;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = client::Client::builder()
    ///     .client_id("your_client_id")
    ///     .client_secret("your_client_secret")
    ///     .instance_url("https://your-instance.my.salesforce.com")
    ///     .build()?
    ///     .connect()
    ///     .await?;
    ///
    /// // Get access token - automatically refreshes if expired
    /// let token = client.access_token().await?;
    /// let bearer = format!("Bearer {}", token.expose_secret());
    /// # let _ = bearer;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn access_token(&self) -> Result<SecretString, Error> {
        let token_state_arc = self.token_state.as_ref().ok_or(Error::NotConnected)?;

        // Check if token needs refresh
        let needs_refresh = {
            let state = token_state_arc.read().map_err(|_| Error::LockError)?;

            state.is_expired(DEFAULT_TOKEN_REFRESH_BUFFER_SECONDS)?
        };

        if needs_refresh {
            // Attempt refresh-token flow first. For flows that don't issue a refresh token
            // (e.g. Client Credentials), this returns `NoRefreshToken` and we fall back to
            // re-authenticating via the original auth flow instead.
            match self.refresh_token().await {
                Ok(()) => {}
                Err(Error::NoRefreshToken) => {
                    self.reauthenticate().await?;
                }
                Err(e) => return Err(e),
            }
        }

        // Return access token
        let state = token_state_arc.read().map_err(|_| Error::LockError)?;

        Ok(SecretString::from(state.access_token()))
    }
}

/// Builder for constructing a [`Client`].
///
/// Set each field with its own method, or pass a whole [`Credentials`] the
/// application has loaded.
///
/// # Examples
///
/// ## Field by field
///
/// ```no_run
/// use salesforce_core::client;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = client::Client::builder()
///     .client_id(std::env::var("SFDC_CLIENT_ID")?)
///     .client_secret(std::env::var("SFDC_CLIENT_SECRET")?)
///     .instance_url("https://your-instance.my.salesforce.com")
///     .build()?
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// ## From a JSON file the application reads
///
/// ```no_run
/// use salesforce_core::client::{self, Credentials};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let credentials: Credentials =
///     serde_json::from_str(&std::fs::read_to_string("credentials.json")?)?;
/// let client = client::Client::builder()
///     .credentials(credentials)
///     .build()?
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct Builder {
    client_id: Option<String>,
    client_secret: Option<SecretString>,
    username: Option<String>,
    password: Option<SecretString>,
    instance_url: Option<String>,
    tenant_id: Option<String>,
    auth_flow: Option<AuthFlow>,
}

impl Builder {
    /// Creates a new builder.
    ///
    /// # Returns
    ///
    /// A `Builder` instance for configuring the Salesforce client.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets every credential field at once, replacing earlier values.
    ///
    /// # Returns
    ///
    /// `Self` for method chaining.
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        let Credentials {
            client_id,
            client_secret,
            username,
            password,
            instance_url,
            tenant_id,
        } = credentials;
        self.client_id = Some(client_id);
        self.client_secret = client_secret;
        self.username = username;
        self.password = password;
        self.instance_url = Some(instance_url);
        self.tenant_id = tenant_id;
        self
    }

    /// Client ID (Consumer Key) from the Connected App.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Client Secret (Consumer Secret) from the Connected App.
    pub fn client_secret(mut self, client_secret: impl Into<SecretString>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Username for [`AuthFlow::UsernamePassword`].
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Password for [`AuthFlow::UsernamePassword`]. If your org requires a
    /// security token, append it to the password.
    pub fn password(mut self, password: impl Into<SecretString>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Instance URL (e.g. `https://mydomain.my.salesforce.com`). The token
    /// is requested from this host.
    pub fn instance_url(mut self, instance_url: impl Into<String>) -> Self {
        self.instance_url = Some(instance_url.into());
        self
    }

    /// Organization ID (15 or 18 characters). Only the Pub/Sub API needs it.
    pub fn tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
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
    /// Returns an error if:
    /// - The client ID or instance URL is missing ([`Error::MissingClientId`], [`Error::MissingInstanceUrl`])
    /// - The instance URL is not an absolute URL ([`Error::ParseUrl`])
    /// - A field the auth flow needs is missing ([`Error::MissingClientSecret`], [`Error::MissingUsername`], [`Error::MissingPassword`])
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub fn build(self) -> Result<Client, Error> {
        let auth_flow = self.auth_flow.unwrap_or_default();
        let client_id = self.client_id.ok_or(Error::MissingClientId)?;
        let instance_url = self.instance_url.ok_or(Error::MissingInstanceUrl)?;
        url::Url::parse(&instance_url).map_err(|source| Error::ParseUrl { source })?;
        if self.client_secret.is_none() {
            return Err(Error::MissingClientSecret);
        }
        if auth_flow == AuthFlow::UsernamePassword {
            if self.username.is_none() {
                return Err(Error::MissingUsername);
            }
            if self.password.is_none() {
                return Err(Error::MissingPassword);
            }
        }

        Ok(Client {
            credentials: Credentials {
                client_id,
                client_secret: self.client_secret,
                username: self.username,
                password: self.password,
                instance_url,
                tenant_id: self.tenant_id,
            },
            auth_flow,
            token_state: None,
            instance_url: None,
            tenant_id: None,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn builder() -> Builder {
        Builder::new()
            .client_id("test_client_id")
            .client_secret("test_secret")
            .instance_url("https://test.salesforce.com")
    }

    #[test]
    fn test_build_without_client_id() {
        let client = Builder::new()
            .client_secret("test_secret")
            .instance_url("https://test.salesforce.com")
            .build();
        assert!(matches!(client, Err(Error::MissingClientId)));
    }

    #[test]
    fn test_build_without_instance_url() {
        let client = Builder::new()
            .client_id("test_client_id")
            .client_secret("test_secret")
            .build();
        assert!(matches!(client, Err(Error::MissingInstanceUrl)));
    }

    #[test]
    fn test_build_with_relative_instance_url() {
        let client = builder().instance_url("mydomain.salesforce.com").build();
        assert!(matches!(client, Err(Error::ParseUrl { .. })));
    }

    #[test]
    fn test_build_without_tenant_id() {
        assert!(builder().build().is_ok());
    }

    #[test]
    fn test_credentials_debug_redacts_secrets() {
        let credentials = Credentials {
            client_id: "id".to_string(),
            client_secret: Some("client-secret-value".into()),
            username: Some("user@example.com".to_string()),
            password: Some("password-value".into()),
            instance_url: "https://localhost".to_string(),
            tenant_id: None,
        };
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("client-secret-value"));
        assert!(!debug.contains("password-value"));
    }

    #[test]
    fn test_credentials_deserialize_without_optional_fields() {
        let credentials: Credentials = serde_json::from_str(
            r#"{"client_id": "id", "instance_url": "https://localhost", "extra": 1}"#,
        )
        .unwrap();
        assert!(credentials.client_secret.is_none());
        assert!(credentials.tenant_id.is_none());
    }

    #[test]
    fn test_setters_override_credentials() {
        let client = Builder::new()
            .credentials(Credentials {
                client_id: "id".to_string(),
                client_secret: None,
                username: None,
                password: None,
                instance_url: "https://localhost".to_string(),
                tenant_id: None,
            })
            .client_secret("secret")
            .tenant_id("tenant")
            .build()
            .unwrap();
        assert_eq!(client.credentials.tenant_id.as_deref(), Some("tenant"));
    }

    #[tokio::test]
    async fn test_connect_with_invalid_credentials() {
        let client = builder().build().unwrap();
        let result = client.connect().await;
        // Should fail with OAuth2RequestFailed (invalid credentials return HTTP error)
        assert!(matches!(result, Err(Error::OAuth2RequestFailed { .. })));
    }

    #[test]
    fn test_client_credentials_flow_missing_secret() {
        let result = Builder::new()
            .client_id("test_client_id")
            .instance_url("https://test.salesforce.com")
            .auth_flow(AuthFlow::ClientCredentials)
            .build();
        assert!(matches!(result, Err(Error::MissingClientSecret)));
    }

    #[test]
    fn test_username_password_flow_missing_username() {
        let result = builder()
            .password("test_password")
            .auth_flow(AuthFlow::UsernamePassword)
            .build();
        assert!(matches!(result, Err(Error::MissingUsername)));
    }

    #[test]
    fn test_username_password_flow_missing_password() {
        let result = builder()
            .username("test_user")
            .auth_flow(AuthFlow::UsernamePassword)
            .build();
        assert!(matches!(result, Err(Error::MissingPassword)));
    }

    #[tokio::test]
    async fn test_username_password_flow_with_valid_fields() {
        let client = builder()
            .username("test_user")
            .password("test_password")
            .auth_flow(AuthFlow::UsernamePassword)
            .build()
            .unwrap();
        let result = client.connect().await;
        // Should fail with OAuth2RequestFailed (invalid credentials return HTTP error, but validation passed)
        assert!(matches!(result, Err(Error::OAuth2RequestFailed { .. })));
    }

    #[test]
    fn test_username_password_flow_missing_client_secret() {
        let result = Builder::new()
            .client_id("test_client_id")
            .instance_url("https://test.salesforce.com")
            .username("test_user")
            .password("test_password")
            .auth_flow(AuthFlow::UsernamePassword)
            .build();
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
        let client = builder().build().unwrap();

        let result = client.current_access_token();
        assert!(matches!(result, Err(Error::NotConnected)));
    }

    #[tokio::test]
    async fn test_access_token_without_connection() {
        let client = builder().build().unwrap();

        let result = client.access_token().await;
        assert!(matches!(result, Err(Error::NotConnected)));
    }

    #[tokio::test]
    async fn test_access_token_reauthenticates_when_expired_and_no_refresh_token() {
        use oauth2::basic::BasicTokenResponse;
        use oauth2::AccessToken;
        use std::time::Duration;

        // Build a connected client with an already-expired token (no refresh token,
        // as the Client Credentials flow returns).
        let mut client = builder().build().unwrap();

        // Inject an expired token with no refresh token to simulate Client Credentials expiry.
        let mut token_response = BasicTokenResponse::new(
            AccessToken::new("expired_token".to_string()),
            oauth2::basic::BasicTokenType::Bearer,
            EmptyExtraTokenFields {},
        );
        token_response.set_expires_in(Some(&Duration::from_secs(0)));
        let token_state = TokenState::new(token_response).unwrap();
        client.token_state = Some(Arc::new(RwLock::new(token_state)));
        client.instance_url = Some("https://test.salesforce.com".to_string());
        client.tenant_id = Some("test_tenant".to_string());

        // access_token() should attempt refresh_token() (fails with NoRefreshToken),
        // then fall back to reauthenticate() which calls Salesforce and fails with
        // OAuth2RequestFailed (invalid credentials) - NOT NoRefreshToken.
        let result = client.access_token().await;
        assert!(
            matches!(result, Err(Error::OAuth2RequestFailed { .. })),
            "expected OAuth2RequestFailed from reauthenticate fallback, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_reconnect_without_connection() {
        let mut client = builder().build().unwrap();

        // Reconnect should fail with OAuth2RequestFailed since we have invalid credentials
        let result = client.reconnect().await;
        assert!(matches!(result, Err(Error::OAuth2RequestFailed { .. })));
    }

    #[test]
    fn test_is_retryable_oauth2_status() {
        assert!(Error::OAuth2RequestFailed {
            status: 429,
            body: String::new()
        }
        .is_retryable());
        assert!(Error::OAuth2RequestFailed {
            status: 503,
            body: String::new()
        }
        .is_retryable());
        assert!(Error::OAuth2RequestFailed {
            status: 500,
            body: String::new()
        }
        .is_retryable());
        assert!(!Error::OAuth2RequestFailed {
            status: 400,
            body: String::new()
        }
        .is_retryable());
        assert!(!Error::OAuth2RequestFailed {
            status: 401,
            body: String::new()
        }
        .is_retryable());
    }

    #[test]
    fn test_is_retryable_config_errors() {
        assert!(!Error::MissingClientId.is_retryable());
        assert!(!Error::MissingInstanceUrl.is_retryable());
        assert!(!Error::MissingClientSecret.is_retryable());
        assert!(!Error::MissingUsername.is_retryable());
        assert!(!Error::MissingPassword.is_retryable());
        assert!(!Error::NoRefreshToken.is_retryable());
        assert!(!Error::NotConnected.is_retryable());
        assert!(!Error::LockError.is_retryable());
        assert!(!Error::TokenExpiryOverflow.is_retryable());
        assert!(!Error::TimeThresholdOverflow.is_retryable());
    }
}
