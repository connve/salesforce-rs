//! Bulk API v2.0 Query operations for asynchronously querying large data sets.

use super::Client as BulkClient;
use crate::client;
use crate::http::{check_path_segments, InvalidPathSegment};
use salesforce_core_bulkapi::types::{CreateQueryJobRequest, ErrorResponse, QueryJobInfo};
use salesforce_core_bulkapi::{ByteStream, Client as GeneratedClient, Error as GeneratedError};
use std::fmt;
use std::num::NonZeroU64;

/// One page of a query job's results, from [`QueryClient::get_results`].
#[non_exhaustive]
pub struct QueryResults {
    /// CSV data for this page.
    pub body: ByteStream,
    /// Locator for the next page, or `None` on the last page. Pass it to
    /// [`QueryClient::get_results`] to fetch the next page.
    pub locator: Option<String>,
    /// Number of records in this page, from `Sforce-NumberOfRecords`.
    pub number_of_records: Option<u64>,
}

impl fmt::Debug for QueryResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryResults")
            .field("locator", &self.locator)
            .field("number_of_records", &self.number_of_records)
            .finish_non_exhaustive()
    }
}

impl QueryResults {
    fn from_response(response: salesforce_core_bulkapi::ResponseValue<ByteStream>) -> Self {
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        // Salesforce marks the last page with the literal string "null".
        let locator = header("Sforce-Locator").filter(|l| !l.is_empty() && l != "null");
        let number_of_records = header("Sforce-NumberOfRecords").and_then(|n| n.parse().ok());
        Self {
            body: response.into_inner(),
            locator,
            number_of_records,
        }
    }
}

#[derive(Debug)]
enum Cursor {
    First,
    Next(String),
    Done,
}

/// Every page of a query job's results, from [`QueryClient::result_pages`].
///
/// A failed request leaves the position unchanged, so calling
/// [`next_page`](Self::next_page) again retries the same page.
#[must_use = "pages do nothing until `.next_page().await` is called"]
#[derive(Debug)]
pub struct Pages<'a> {
    query_client: &'a QueryClient,
    job_id: String,
    max_records: Option<NonZeroU64>,
    cursor: Cursor,
}

impl Pages<'_> {
    /// The next page, or `None` after the last one.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn next_page(&mut self) -> Option<Result<QueryResults, Error>> {
        let locator = match &self.cursor {
            Cursor::First => None,
            Cursor::Next(locator) => Some(locator.as_str()),
            Cursor::Done => return None,
        };
        let result = self
            .query_client
            .get_results(&self.job_id, self.max_records, locator)
            .await;
        if let Ok(page) = &result {
            self.cursor = match &page.locator {
                Some(locator) => Cursor::Next(locator.clone()),
                None => Cursor::Done,
            };
        }
        Some(result)
    }
}

/// Client for Bulk API v2.0 Query operations.
///
/// Use this client to create and manage query jobs for extracting large amounts
/// of data from Salesforce using SOQL queries.
#[derive(Clone, Debug)]
pub struct QueryClient {
    bulk_client: BulkClient,
}

impl QueryClient {
    /// Creates a new query client.
    pub(crate) fn new(bulk_client: BulkClient) -> Self {
        Self { bulk_client }
    }

    /// The generated client, backed by the cached HTTP client so connections
    /// are reused across calls.
    async fn generated(&self) -> Result<GeneratedClient, Error> {
        let http_client = self
            .bulk_client
            .get_http_client()
            .await
            .map_err(|e| match e {
                crate::http::Error::Auth { source } => Error::Auth { source },
                crate::http::Error::Build { source } => Error::Communication { source },
            })?;
        let base_url = self
            .bulk_client
            .base_url()
            .map_err(|source| Error::Auth { source })?;
        Ok(GeneratedClient::new_with_client(&base_url, http_client))
    }

    /// Creates a new bulk query job.
    ///
    /// # Arguments
    ///
    /// * `request` - The query job creation request containing the SOQL query and options
    ///
    /// # Returns
    ///
    /// Information about the created job, including the job ID needed to retrieve results.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::bulkapi::{ClientBuilder, CreateQueryJobRequest, QueryOperation};
    /// # use salesforce_core::client;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Client::builder()
    /// #     .client_id("...")
    /// #     .client_secret("...")
    /// #     .instance_url("https://your-instance.my.salesforce.com")
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build()?;
    /// let query_client = bulk_client.query();
    ///
    /// let job = query_client
    ///     .create_job(&CreateQueryJobRequest {
    ///         operation: QueryOperation::Query,
    ///         query: "SELECT Id, Name FROM Account WHERE Industry = 'Technology'".to_string(),
    ///         content_type: None,
    ///         column_delimiter: None,
    ///         line_ending: None,
    ///     })
    ///     .await?;
    ///
    /// println!("Created job: {}", job.id);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn create_job(&self, request: &CreateQueryJobRequest) -> Result<QueryJobInfo, Error> {
        let client = self.generated().await?;

        let response = client
            .create_query_job(request)
            .await
            .map_err(classify_generated_error)?;
        Ok(response.into_inner())
    }

    /// Retrieves information about a query job.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the query job
    ///
    /// # Returns
    ///
    /// Detailed information about the job including its state and processing metrics.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client;
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Client::builder()
    /// #     .client_id("...")
    /// #     .client_secret("...")
    /// #     .instance_url("https://your-instance.my.salesforce.com")
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build()?;
    /// let query_client = bulk_client.query();
    ///
    /// let job_info = query_client.get_job("750xx0000000001AAA").await?;
    /// println!("Job state: {:?}", job_info.state);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_job(&self, job_id: &str) -> Result<QueryJobInfo, Error> {
        require_path_segments(&[job_id])?;
        let client = self.generated().await?;

        let response = client
            .get_query_job(job_id)
            .await
            .map_err(classify_generated_error)?;
        Ok(response.into_inner())
    }

    /// Retrieves one page of the results of a completed query job.
    ///
    /// Large result sets span several pages. The returned
    /// [`QueryResults::locator`] points at the next page and is `None` on the
    /// last one. [`result_pages`](Self::result_pages) walks every page for you.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the query job
    /// * `max_records` - Optional maximum number of records to return per
    ///   request; `NonZeroU64::new(n)` builds it from a plain number
    /// * `locator` - `None` for the first page, then the previous page's
    ///   [`QueryResults::locator`]
    ///
    /// # Returns
    ///
    /// The page's CSV data, the locator for the next page, and the page's
    /// record count.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use futures_util::StreamExt;
    /// use std::num::NonZeroU64;
    /// # use salesforce_core::client;
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Client::builder()
    /// #     .client_id("...")
    /// #     .client_secret("...")
    /// #     .instance_url("https://your-instance.my.salesforce.com")
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build()?;
    /// let query_client = bulk_client.query();
    ///
    /// let mut locator = None;
    /// loop {
    ///     let mut page = query_client
    ///         .get_results("750xx0000000001AAA", NonZeroU64::new(5000), locator.as_deref())
    ///         .await?;
    ///     while let Some(chunk) = page.body.next().await {
    ///         let chunk = chunk?;
    ///         // Process chunk...
    ///     }
    ///     match page.locator {
    ///         Some(next) => locator = Some(next),
    ///         None => break,
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_results(
        &self,
        job_id: &str,
        max_records: Option<NonZeroU64>,
        locator: Option<&str>,
    ) -> Result<QueryResults, Error> {
        require_path_segments(&[job_id])?;
        let client = self.generated().await?;
        let response = client
            .get_query_job_results(job_id, locator, max_records)
            .await
            .map_err(classify_generated_error)?;
        Ok(QueryResults::from_response(response))
    }

    /// Iterates over every page of the results of a completed query job,
    /// following [`QueryResults::locator`] until the last page.
    ///
    /// Pages are fetched one after another. To download them in parallel,
    /// use [`get_result_pages`](Self::get_result_pages).
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the query job
    /// * `max_records` - Optional maximum number of records per page
    ///
    /// # Example
    ///
    /// ```no_run
    /// use futures_util::StreamExt;
    /// # use salesforce_core::client;
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Client::builder()
    /// #     .client_id("...")
    /// #     .client_secret("...")
    /// #     .instance_url("https://your-instance.my.salesforce.com")
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build()?;
    /// let query_client = bulk_client.query();
    ///
    /// let mut pages = query_client.result_pages("750xx0000000001AAA", None);
    /// while let Some(page) = pages.next_page().await {
    ///     let mut body = page?.body;
    ///     while let Some(chunk) = body.next().await {
    ///         let chunk = chunk?;
    ///         // Process chunk...
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn result_pages(
        &self,
        job_id: impl Into<String>,
        max_records: Option<NonZeroU64>,
    ) -> Pages<'_> {
        Pages {
            query_client: self,
            job_id: job_id.into(),
            max_records,
            cursor: Cursor::First,
        }
    }

    /// Deletes a query job.
    ///
    /// Once deleted, the job and its results can no longer be retrieved.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the query job to delete
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client;
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Client::builder()
    /// #     .client_id("...")
    /// #     .client_secret("...")
    /// #     .instance_url("https://your-instance.my.salesforce.com")
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build()?;
    /// let query_client = bulk_client.query();
    ///
    /// query_client.delete_job("750xx0000000001AAA").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn delete_job(&self, job_id: &str) -> Result<(), Error> {
        require_path_segments(&[job_id])?;
        let client = self.generated().await?;

        client
            .delete_query_job(job_id)
            .await
            .map_err(classify_generated_error)?;
        Ok(())
    }

    /// Aborts a query job.
    ///
    /// This stops processing of the job but does not delete it. The job state
    /// will be changed to Aborted.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the query job to abort
    ///
    /// # Returns
    ///
    /// Updated job information showing the Aborted state.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client;
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Client::builder()
    /// #     .client_id("...")
    /// #     .client_secret("...")
    /// #     .instance_url("https://your-instance.my.salesforce.com")
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build()?;
    /// let query_client = bulk_client.query();
    ///
    /// let job_info = query_client.abort_job("750xx0000000001AAA").await?;
    /// println!("Job state: {:?}", job_info.state);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn abort_job(&self, job_id: &str) -> Result<QueryJobInfo, Error> {
        use salesforce_core_bulkapi::types::{AbortQueryJobBody, AbortQueryJobBodyState};

        require_path_segments(&[job_id])?;
        let client = self.generated().await?;

        let response = client
            .abort_query_job(
                job_id,
                &AbortQueryJobBody {
                    state: AbortQueryJobBodyState::Aborted,
                },
            )
            .await
            .map_err(classify_generated_error)?;
        Ok(response.into_inner())
    }

    /// Retrieves information about all query jobs.
    ///
    /// This method supports filtering and pagination.
    ///
    /// # Arguments
    ///
    /// * `is_pk_chunking_enabled` - Optional filter for jobs with PK chunking enabled (Bulk API jobs only)
    /// * `job_type` - Optional filter by job type
    /// * `concurrency_mode` - Optional filter by concurrency mode (currently only Parallel is supported)
    /// * `query_locator` - Optional pagination locator from a previous response's nextRecordsUrl
    ///
    /// # Returns
    ///
    /// A list of query jobs matching the filter criteria.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client;
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Client::builder()
    /// #     .client_id("...")
    /// #     .client_secret("...")
    /// #     .instance_url("https://your-instance.my.salesforce.com")
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build()?;
    /// let query_client = bulk_client.query();
    ///
    /// let jobs = query_client.get_all_jobs(None, None, None, None).await?;
    /// println!("Found {} jobs", jobs.records.len());
    /// for job in jobs.records {
    ///     println!("Job ID: {}, State: {:?}", job.id, job.state);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_all_jobs(
        &self,
        is_pk_chunking_enabled: Option<bool>,
        job_type: Option<salesforce_core_bulkapi::types::JobType>,
        concurrency_mode: Option<salesforce_core_bulkapi::types::ConcurrencyMode>,
        query_locator: Option<&str>,
    ) -> Result<salesforce_core_bulkapi::types::QueryJobList, Error> {
        let client = self.generated().await?;

        let response = client
            .get_all_query_jobs(
                concurrency_mode,
                is_pk_chunking_enabled,
                job_type,
                query_locator,
            )
            .await
            .map_err(classify_generated_error)?;
        Ok(response.into_inner())
    }

    /// Retrieves result page URLs for parallel processing of a completed query job.
    ///
    /// Returns up to five URIs that can be used to fetch results in parallel.
    /// The job must be in the `JobComplete` state. You must use the same API version
    /// that was used to create the query job.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the query job
    /// * `locator` - Optional locator for pagination of result pages
    ///
    /// # Returns
    ///
    /// A list of result page URLs that can be fetched in parallel, along with
    /// pagination information for retrieving additional pages.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use salesforce_core::client;
    /// # use salesforce_core::bulkapi::ClientBuilder;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Client::builder()
    /// #     .client_id("...")
    /// #     .client_secret("...")
    /// #     .instance_url("https://your-instance.my.salesforce.com")
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let bulk_client = ClientBuilder::new(auth_client).build()?;
    /// let query_client = bulk_client.query();
    ///
    /// let result_pages = query_client.get_result_pages("750R0000000zxr8IAA", None).await?;
    /// println!("Found {} result pages", result_pages.result_pages.len());
    /// for page in result_pages.result_pages {
    ///     println!("Result URL: {}", page.result_url);
    ///     // Fetch each result URL in parallel
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_result_pages(
        &self,
        job_id: &str,
        locator: Option<&str>,
    ) -> Result<salesforce_core_bulkapi::types::QueryResultPages, Error> {
        require_path_segments(&[job_id])?;
        let client = self.generated().await?;

        let response = client
            .get_query_job_result_pages(job_id, locator)
            .await
            .map_err(classify_generated_error)?;
        Ok(response.into_inner())
    }
}

/// Error type for bulk query operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication/client error from salesforce-core.
    #[error("Authentication error: {source}")]
    Auth {
        #[source]
        source: client::Error,
    },

    /// Error from the generated Bulk API client.
    ///
    /// This variant represents errors returned by Salesforce at the API level,
    /// such as HTTP 4xx/5xx responses with a structured error body.
    #[error("Bulk API error: {source}")]
    BulkApi {
        #[source]
        source: Box<GeneratedError<ErrorResponse>>,
    },

    /// Network-level communication failure.
    ///
    /// Covers connection refused, timeouts, TLS errors, HTTP client construction
    /// failures, and errors reading the response body. Callers can use this
    /// variant to distinguish transient infrastructure problems from Salesforce
    /// API errors and apply retry logic accordingly.
    #[error("Communication error: {source}")]
    Communication {
        #[source]
        source: reqwest::Error,
    },

    /// The job ID is empty, `.`, `..`, or contains control characters.
    /// Caught before the request is sent.
    #[error("Invalid path segment `{segment}`")]
    InvalidPathSegment {
        /// The rejected value.
        segment: String,
    },
}

impl Error {
    /// Returns `true` if the error is transient and the operation could
    /// succeed if retried.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Auth { source } => source.is_retryable(),
            Error::BulkApi { source } => source.is_retryable(),
            Error::Communication { source } => source.is_timeout() || source.is_connect(),
            Error::InvalidPathSegment { .. } => false,
        }
    }
}

fn require_path_segments(segments: &[&str]) -> Result<(), Error> {
    check_path_segments(segments)
        .map_err(|InvalidPathSegment { segment }| Error::InvalidPathSegment { segment })
}

/// Transport failures become [`Error::Communication`]; everything else the
/// generated client reports is a Salesforce API error.
fn classify_generated_error(err: GeneratedError<ErrorResponse>) -> Error {
    match err {
        GeneratedError::CommunicationError(source)
        | GeneratedError::InvalidUpgrade(source)
        | GeneratedError::ResponseBodyError(source) => Error::Communication { source },
        other => Error::BulkApi {
            source: Box::new(other),
        },
    }
}
