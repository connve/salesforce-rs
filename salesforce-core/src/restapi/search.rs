//! SOSL search operations implementation.

use super::Client;
use crate::client;
use salesforce_core_restapi::types::SearchResponse;
use salesforce_core_restapi::{Client as GeneratedClient, Error as GeneratedError};

/// Error type for search operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication/client error from salesforce-core.
    #[error("Authentication error: {source}")]
    Auth {
        #[source]
        source: client::Error,
    },

    /// Error from the generated REST API client.
    #[error("Search API error: {source}")]
    SearchApi {
        #[source]
        source: GeneratedError<salesforce_core_restapi::types::ErrorResponse>,
    },

    /// Network-level communication failure.
    #[error("Communication error: {source}")]
    Communication {
        #[source]
        source: reqwest::Error,
    },
}

impl Client {
    /// Executes a SOSL search query.
    ///
    /// # Arguments
    ///
    /// * `sosl_query` - A valid SOSL query string (e.g., "FIND {Acme} IN ALL FIELDS RETURNING Account(Id, Name)")
    ///
    /// # Returns
    ///
    /// A `SearchResponse` containing matching records across the specified SObject types.
    ///
    /// # Example
    ///
    /// ```no_run
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
    /// #         instance_url: "https://your-instance.salesforce.com".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let results = rest_client
    ///     .search("FIND {Acme} IN ALL FIELDS RETURNING Account(Id, Name), Contact(Id, Name)")
    ///     .await?;
    ///
    /// for record in &results.search_records {
    ///     println!("{}: {}", record.attributes.type_, record.id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn search(&self, sosl_query: impl AsRef<str>) -> Result<SearchResponse, Error> {
        let sosl_query = sosl_query.as_ref();
        let http_client = self.get_http_client().await.map_err(|e| match e {
            crate::http::Error::Auth { source } => Error::Auth { source },
            crate::http::Error::InvalidHeader | crate::http::Error::Lock => Error::Auth {
                source: client::Error::LockError,
            },
            crate::http::Error::Build { source } => Error::Communication { source },
        })?;
        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .search(sosl_query)
            .await
            .map_err(|source| Error::SearchApi { source })?;

        Ok(response.into_inner())
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
}
