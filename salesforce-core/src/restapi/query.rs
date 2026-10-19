//! SOQL query operations.
//!
//! Each operation returns a request builder that accepts optional
//! Salesforce-specific headers (for example `Sforce-Query-Options:
//! batchSize=500`) via `.header()` / `.headers()`, then is dispatched with
//! `.send().await`.

use super::headers::{impl_header_methods, HeaderBag, InvalidHeader};
use super::Client;
use salesforce_core_restapi::types::{ErrorResponse, QueryResponse};
use salesforce_core_restapi::{Client as GeneratedClient, Error as GeneratedError};

/// Error type for SOQL query operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication error.
    #[error("Authentication error: {source}")]
    Auth {
        /// The underlying authentication error.
        #[source]
        source: crate::client::Error,
    },

    /// Error from the Salesforce Query API.
    #[error("Salesforce Query API error: {source}")]
    QueryApi {
        /// The underlying API error.
        #[source]
        source: Box<GeneratedError<ErrorResponse>>,
    },

    /// Error building HTTP client.
    #[error("Failed to build HTTP client: {source}")]
    HttpClient {
        /// The underlying reqwest error.
        #[source]
        source: reqwest::Error,
    },

    /// A request header is either reserved (`Authorization`, `Content-Type`,
    /// `Accept`, `Content-Length`, `Transfer-Encoding`, `Host`) or could not be
    /// converted into a valid `HeaderName` / `HeaderValue`.
    #[error("Invalid request header `{name}`")]
    InvalidHeader {
        /// The header name that was rejected.
        name: String,
    },

    /// The value passed to [`Client::query_more`] is neither a
    /// `nextRecordsUrl` nor a bare query locator.
    #[error("Invalid nextRecordsUrl `{url}`")]
    InvalidNextRecordsUrl {
        /// The rejected value.
        url: String,
    },
}

impl Error {
    /// Returns `true` if the error is transient and the operation could
    /// succeed if retried.
    ///
    /// `Auth` and `QueryApi` defer to their source's classification (429 and
    /// 5xx responses and transport failures are retryable), and `HttpClient`
    /// is retryable on a timeout or connect failure. `InvalidHeader` and
    /// `InvalidNextRecordsUrl` are rejected before a request is sent and are
    /// never retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Auth { source } => source.is_retryable(),
            Error::QueryApi { source } => source.is_retryable(),
            Error::HttpClient { source } => source.is_timeout() || source.is_connect(),
            Error::InvalidHeader { .. } | Error::InvalidNextRecordsUrl { .. } => false,
        }
    }
}

/// Extracts the query locator from a `nextRecordsUrl`, or accepts a bare
/// locator as-is.
fn query_locator(next_records_url: &str) -> Option<&str> {
    let locator = match next_records_url.rsplit_once("/query/") {
        Some((_, locator)) => locator,
        None => next_records_url,
    };
    (!locator.contains('/') && crate::http::check_path_segments(&[locator]).is_ok())
        .then_some(locator)
}

/// The generated client for one request: the shared, cached HTTP client plus
/// the request's per-call headers.
async fn generated(client: &Client, headers: HeaderBag) -> Result<GeneratedClient, Error> {
    let headers = headers
        .finish()
        .map_err(|InvalidHeader { name }| Error::InvalidHeader { name })?;
    let http_client = client.get_http_client().await.map_err(|e| match e {
        crate::http::Error::Auth { source } => Error::Auth { source },
        crate::http::Error::Build { source } => Error::HttpClient { source },
    })?;
    let base_url = client.base_url().map_err(|source| Error::Auth { source })?;
    Ok(GeneratedClient::new_with_client(
        &base_url,
        http_client,
        headers,
    ))
}

/// Builder for [`Client::query`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct Query<'a> {
    client: &'a Client,
    soql: String,
    headers: HeaderBag,
}

impl<'a> Query<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<QueryResponse, Error> {
        let gen = generated(self.client, self.headers).await?;
        let response = gen
            .query(&self.soql)
            .await
            .map_err(|source| Error::QueryApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

/// Builder for [`Client::query_all`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct QueryAll<'a> {
    client: &'a Client,
    soql: String,
    headers: HeaderBag,
}

impl<'a> QueryAll<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<QueryResponse, Error> {
        let gen = generated(self.client, self.headers).await?;
        let response = gen
            .query_all(&self.soql)
            .await
            .map_err(|source| Error::QueryApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

/// Builder for [`Client::query_more`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct QueryMore<'a> {
    client: &'a Client,
    next_records_url: String,
    headers: HeaderBag,
}

impl<'a> QueryMore<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    ///
    /// Returns [`Error::InvalidNextRecordsUrl`] without contacting Salesforce
    /// if no query locator can be extracted from the given value.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<QueryResponse, Error> {
        let locator =
            query_locator(&self.next_records_url).ok_or_else(|| Error::InvalidNextRecordsUrl {
                url: self.next_records_url.clone(),
            })?;
        let gen = generated(self.client, self.headers).await?;
        let response = gen
            .query_more(locator)
            .await
            .map_err(|source| Error::QueryApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

impl Client {
    /// Builds a request that executes a SOQL query and returns the first
    /// batch of results.
    ///
    /// Any queryable object can be targeted, including custom settings and
    /// custom metadata types. When the response has `done: false`, pass its
    /// `next_records_url` to [`Client::query_more`] to fetch the next batch.
    /// Batch size defaults to 2,000 records and can be lowered with the
    /// `Sforce-Query-Options: batchSize=<n>` header.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client;
    /// use salesforce_core::restapi;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Client::builder()
    /// #     .client_id("...")
    /// #     .client_secret("...")
    /// #     .instance_url("https://localhost")
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let rest = restapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let mut page = rest
    ///     .query("SELECT Name, Value__c FROM My_Setting__c")
    ///     .send()
    ///     .await?;
    /// let mut records = page.records;
    /// while let Some(next) = page.next_records_url {
    ///     page = rest.query_more(next).send().await?;
    ///     records.append(&mut page.records);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn query(&self, soql: impl Into<String>) -> Query<'_> {
        Query {
            client: self,
            soql: soql.into(),
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request that executes a SOQL query including records deleted
    /// into the Recycle Bin, records removed by a merge, and archived
    /// activities (the `queryAll` resource).
    ///
    /// Remaining batches are fetched with [`Client::query_more`], as for
    /// [`Client::query`].
    pub fn query_all(&self, soql: impl Into<String>) -> QueryAll<'_> {
        QueryAll {
            client: self,
            soql: soql.into(),
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request that fetches the next batch of a query whose
    /// previous response had `done: false`.
    ///
    /// Accepts either the response's `next_records_url` as returned (a path
    /// ending in `/query/<locator>`) or the bare query locator.
    pub fn query_more(&self, next_records_url: impl Into<String>) -> QueryMore<'_> {
        QueryMore {
            client: self,
            next_records_url: next_records_url.into(),
            headers: HeaderBag::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_locator_from_next_records_url() {
        assert_eq!(
            query_locator(&format!(
                "/services/data/v{}/query/01gxx0000002GJm-2000",
                crate::DEFAULT_API_VERSION
            )),
            Some("01gxx0000002GJm-2000")
        );
    }

    #[test]
    fn test_query_locator_accepts_bare_locator() {
        assert_eq!(
            query_locator("01gxx0000002GJm-2000"),
            Some("01gxx0000002GJm-2000")
        );
    }

    #[test]
    fn test_query_locator_rejects_empty() {
        assert_eq!(query_locator(""), None);
        assert_eq!(
            query_locator(&format!(
                "/services/data/v{}/query/",
                crate::DEFAULT_API_VERSION
            )),
            None
        );
    }

    #[test]
    fn test_query_locator_rejects_dot_segments() {
        assert_eq!(query_locator(".."), None);
        assert_eq!(
            query_locator(&format!(
                "/services/data/v{}/query/..",
                crate::DEFAULT_API_VERSION
            )),
            None
        );
    }

    #[test]
    fn test_query_locator_rejects_unrelated_path() {
        assert_eq!(
            query_locator(&format!(
                "/services/data/v{}/sobjects/Account",
                crate::DEFAULT_API_VERSION
            )),
            None
        );
    }

    #[test]
    fn test_invalid_next_records_url_is_not_retryable() {
        let error = Error::InvalidNextRecordsUrl { url: String::new() };
        assert!(!error.is_retryable());
    }
}
