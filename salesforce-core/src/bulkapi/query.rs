//! Bulk API v2.0 Query operations for asynchronously querying large data sets.

use super::Client as BulkClient;
use crate::client;
use salesforce_core_v1::types::{CreateQueryJobRequest, QueryJobInfo};
use salesforce_core_v1::{ByteStream, Client as GeneratedClient, Error as GeneratedError};

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

    /// Helper to build an HTTP client with authentication headers and connection pooling.
    async fn build_http_client(&self) -> Result<reqwest::Client, Error> {
        let token = self
            .bulk_client
            .auth_client()
            .access_token()
            .await
            .map_err(|source| Error::Auth { source })?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| Error::Auth {
                    source: client::Error::LockError,
                })?,
        );

        reqwest::ClientBuilder::new()
            .default_headers(headers)
            .connect_timeout(self.bulk_client.connect_timeout())
            .timeout(self.bulk_client.request_timeout())
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build()
            .map_err(|source| Error::Auth {
                source: client::Error::HttpClientBuild { source },
            })
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
    /// # use salesforce_core::client::{self, Credentials};
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
    /// let bulk_client = ClientBuilder::new(auth_client).build();
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
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .create_query_job(request)
            .await
            .map_err(|source| Error::BulkApi { source })?;
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
    /// let query_client = bulk_client.query();
    ///
    /// let job_info = query_client.get_job("750xx0000000001AAA").await?;
    /// println!("Job state: {:?}", job_info.state);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_job(&self, job_id: &str) -> Result<QueryJobInfo, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_query_job(job_id)
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(response.into_inner())
    }

    /// Retrieves the results of a completed query job.
    ///
    /// Results are returned as a CSV stream. For large result sets, use pagination
    /// with the `locator` parameter.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the query job
    /// * `max_records` - Optional maximum number of records to return per request
    /// * `locator` - Optional locator for pagination (from previous response headers)
    ///
    /// # Returns
    ///
    /// A byte stream containing CSV data with the query results.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use futures_util::StreamExt;
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
    /// let query_client = bulk_client.query();
    ///
    /// let mut results = query_client
    ///     .get_results("750xx0000000001AAA", Some(5000), None)
    ///     .await?;
    ///
    /// // Stream the CSV data
    /// while let Some(chunk) = results.next().await {
    ///     let chunk = chunk?;
    ///     // Process chunk...
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_results(
        &self,
        job_id: &str,
        max_records: Option<i64>,
        locator: Option<&str>,
    ) -> Result<ByteStream, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_query_job_results(job_id, locator, max_records)
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(response.into_inner())
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
    /// let query_client = bulk_client.query();
    ///
    /// query_client.delete_job("750xx0000000001AAA").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn delete_job(&self, job_id: &str) -> Result<(), Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        client
            .delete_query_job(job_id)
            .await
            .map_err(|source| Error::BulkApi { source })?;
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
    /// let query_client = bulk_client.query();
    ///
    /// let job_info = query_client.abort_job("750xx0000000001AAA").await?;
    /// println!("Job state: {:?}", job_info.state);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn abort_job(&self, job_id: &str) -> Result<QueryJobInfo, Error> {
        use salesforce_core_v1::types::{AbortQueryJobBody, AbortQueryJobBodyState};

        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .abort_query_job(
                job_id,
                &AbortQueryJobBody {
                    state: AbortQueryJobBodyState::Aborted,
                },
            )
            .await
            .map_err(|source| Error::BulkApi { source })?;
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
        job_type: Option<salesforce_core_v1::types::JobType>,
        concurrency_mode: Option<salesforce_core_v1::types::ConcurrencyMode>,
        query_locator: Option<&str>,
    ) -> Result<salesforce_core_v1::types::QueryJobList, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_all_query_jobs(concurrency_mode, is_pk_chunking_enabled, job_type, query_locator)
            .await
            .map_err(|source| Error::BulkApi { source })?;
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
    ) -> Result<salesforce_core_v1::types::QueryResultPages, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_query_job_result_pages(job_id, locator)
            .await
            .map_err(|source| Error::BulkApi { source })?;
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
    #[error("Bulk API error: {source}")]
    BulkApi {
        #[source]
        source: GeneratedError<salesforce_core_v1::types::ErrorResponse>,
    },
}

#[cfg(test)]
mod tests {
}
