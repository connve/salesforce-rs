//! Error types for Tooling API operations.

use crate::client;

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
