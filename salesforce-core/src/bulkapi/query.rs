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
    /// use salesforce_core::bulkapi::QueryOperation;
    /// use salesforce_core_v1::types::CreateQueryJobRequest;
    /// # use salesforce_core::client::{self, Credentials};
    /// # use salesforce_core::bulkapi::Client as BulkClient;
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
    /// let bulk_client = BulkClient::new(auth_client, "58.0");
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
    pub async fn create_job(
        &self,
        request: &CreateQueryJobRequest,
    ) -> Result<QueryJobInfo, Error> {
        let http_client = self.bulk_client.build_http_client().await.map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&self.bulk_client.base_url(), http_client);

        let response = client.create_query_job(request).await.map_err(|source| Error::BulkApi { source })?;
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
    /// let query_client = bulk_client.query();
    ///
    /// let job_info = query_client.get_job("750xx0000000001AAA").await?;
    /// println!("Job state: {:?}", job_info.state);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_job(&self, job_id: &str) -> Result<QueryJobInfo, Error> {
        let http_client = self.bulk_client.build_http_client().await.map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&self.bulk_client.base_url(), http_client);

        let response = client.get_query_job(job_id).await.map_err(|source| Error::BulkApi { source })?;
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
        let http_client = self.bulk_client.build_http_client().await.map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&self.bulk_client.base_url(), http_client);

        let response = client
            .get_query_job_results(job_id, locator, max_records)
            .await.map_err(|source| Error::BulkApi { source })?;
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
