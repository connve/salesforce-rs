//! Bulk API v2.0 Ingest operations for loading, updating, or deleting large data sets.

use super::Client as BulkClient;
use crate::client;
use salesforce_core_v1::types::{CreateIngestJobRequest, IngestJobInfo};
use salesforce_core_v1::{Client as GeneratedClient, Error as GeneratedError};

/// Client for Bulk API v2.0 Ingest operations.
///
/// Use this client to create and manage ingest jobs for loading, updating,
/// upserting, or deleting large numbers of records in Salesforce.
#[derive(Clone, Debug)]
pub struct IngestClient {
    bulk_client: BulkClient,
}

impl IngestClient {
    /// Creates a new ingest client.
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
            .tcp_keepalive(std::time::Duration::from_secs(
                crate::DEFAULT_TCP_KEEPALIVE_SECS,
            ))
            .pool_max_idle_per_host(crate::DEFAULT_POOL_MAX_IDLE_PER_HOST)
            .pool_idle_timeout(std::time::Duration::from_secs(
                crate::DEFAULT_POOL_IDLE_TIMEOUT_SECS,
            ))
            .build()
            .map_err(|source| Error::Auth {
                source: client::Error::HttpClientBuild { source },
            })
    }

    /// Creates a new bulk ingest job.
    ///
    /// After creating the job, you'll need to upload data to it and then close
    /// the job to begin processing.
    ///
    /// # Arguments
    ///
    /// * `request` - The ingest job creation request specifying the object and operation
    ///
    /// # Returns
    ///
    /// Information about the created job, including the job ID and content URL for data upload.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::bulkapi::{ClientBuilder, CreateIngestJobRequest, IngestOperation};
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
    /// let ingest_client = bulk_client.ingest();
    ///
    /// let job = ingest_client
    ///     .create_job(&CreateIngestJobRequest {
    ///         object: "Account".to_string(),
    ///         operation: IngestOperation::Insert,
    ///         content_type: None,
    ///         external_id_field_name: None,
    ///         assignment_rule_id: None,
    ///         column_delimiter: None,
    ///         line_ending: None,
    ///     })
    ///     .await?;
    ///
    /// println!("Created job: {}", job.id);
    /// println!("Upload data to: {}", job.content_url.unwrap_or_default());
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn create_job(
        &self,
        request: &CreateIngestJobRequest,
    ) -> Result<IngestJobInfo, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .create_ingest_job(request)
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(response.into_inner())
    }

    /// Retrieves information about an ingest job.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the ingest job
    ///
    /// # Returns
    ///
    /// Detailed information about the job including its state, processing metrics,
    /// and success/failure counts.
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
    /// let ingest_client = bulk_client.ingest();
    ///
    /// let job_info = ingest_client.get_job("750xx0000000002AAA").await?;
    /// println!("Job state: {:?}", job_info.state);
    /// println!("Records processed: {:?}", job_info.number_records_processed);
    /// println!("Records failed: {:?}", job_info.number_records_failed);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_job(&self, job_id: &str) -> Result<IngestJobInfo, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_ingest_job(job_id)
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(response.into_inner())
    }

    /// Uploads CSV data to an ingest job.
    ///
    /// The job must be in the Open state. Data must not exceed 100 MB to account
    /// for base64 encoding overhead.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the ingest job
    /// * `csv_data` - CSV data as bytes
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
    /// let ingest_client = bulk_client.ingest();
    ///
    /// let csv_data = b"Name,Phone\nAcme Inc,555-1234\nGlobal Corp,555-5678";
    /// ingest_client.upload_data("750xx0000000002AAA", csv_data).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn upload_data(&self, job_id: &str, csv_data: &[u8]) -> Result<(), Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        client
            .upload_ingest_job_data(job_id, csv_data.to_vec())
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(())
    }

    /// Marks an ingest job as upload complete and ready for processing.
    ///
    /// After calling this, no more data can be added to the job.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the ingest job
    ///
    /// # Returns
    ///
    /// Updated job information with state set to UploadComplete.
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
    /// let ingest_client = bulk_client.ingest();
    ///
    /// let job_info = ingest_client.mark_upload_complete("750xx0000000002AAA").await?;
    /// println!("Job state: {:?}", job_info.state);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn mark_upload_complete(&self, job_id: &str) -> Result<IngestJobInfo, Error> {
        use salesforce_core_v1::types::{JobState, UpdateIngestJobStateBody};

        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .update_ingest_job_state(
                job_id,
                &UpdateIngestJobStateBody {
                    state: JobState::UploadComplete,
                },
            )
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(response.into_inner())
    }

    /// Aborts an ingest job.
    ///
    /// This stops processing of the job but does not delete it. The job state
    /// will be changed to Aborted.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the ingest job to abort
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
    /// let ingest_client = bulk_client.ingest();
    ///
    /// let job_info = ingest_client.abort_job("750xx0000000002AAA").await?;
    /// println!("Job state: {:?}", job_info.state);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn abort_job(&self, job_id: &str) -> Result<IngestJobInfo, Error> {
        use salesforce_core_v1::types::{JobState, UpdateIngestJobStateBody};

        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .update_ingest_job_state(
                job_id,
                &UpdateIngestJobStateBody {
                    state: JobState::Aborted,
                },
            )
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(response.into_inner())
    }

    /// Deletes an ingest job.
    ///
    /// The job must be in UploadComplete, JobComplete, Aborted, or Failed state.
    /// Once deleted, the job and its data cannot be retrieved.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the ingest job to delete
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
    /// let ingest_client = bulk_client.ingest();
    ///
    /// ingest_client.delete_job("750xx0000000002AAA").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn delete_job(&self, job_id: &str) -> Result<(), Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        client
            .delete_ingest_job(job_id)
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(())
    }

    /// Retrieves successfully processed records for a completed job.
    ///
    /// Returns CSV data with sf__Created, sf__Id, and original record fields.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the ingest job
    ///
    /// # Returns
    ///
    /// A byte stream containing CSV data with successful records.
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
    /// let ingest_client = bulk_client.ingest();
    ///
    /// let mut results = ingest_client.get_successful_results("750xx0000000002AAA").await?;
    /// while let Some(chunk) = results.next().await {
    ///     let chunk = chunk?;
    ///     // Process chunk...
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_successful_results(
        &self,
        job_id: &str,
    ) -> Result<salesforce_core_v1::ByteStream, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_ingest_job_successful_results(job_id)
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(response.into_inner())
    }

    /// Retrieves failed records for a completed job.
    ///
    /// Returns CSV data with sf__Error, sf__Id, and original record fields.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the ingest job
    ///
    /// # Returns
    ///
    /// A byte stream containing CSV data with failed records and error information.
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
    /// let ingest_client = bulk_client.ingest();
    ///
    /// let mut results = ingest_client.get_failed_results("750xx0000000002AAA").await?;
    /// while let Some(chunk) = results.next().await {
    ///     let chunk = chunk?;
    ///     // Process chunk...
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_failed_results(
        &self,
        job_id: &str,
    ) -> Result<salesforce_core_v1::ByteStream, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_ingest_job_failed_results(job_id)
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(response.into_inner())
    }

    /// Retrieves unprocessed records for a failed or aborted job.
    ///
    /// Returns CSV data with original record fields for records that were not processed.
    ///
    /// # Arguments
    ///
    /// * `job_id` - The unique identifier of the ingest job
    ///
    /// # Returns
    ///
    /// A byte stream containing CSV data with unprocessed records.
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
    /// let ingest_client = bulk_client.ingest();
    ///
    /// let mut results = ingest_client.get_unprocessed_results("750xx0000000002AAA").await?;
    /// while let Some(chunk) = results.next().await {
    ///     let chunk = chunk?;
    ///     // Process chunk...
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn get_unprocessed_results(
        &self,
        job_id: &str,
    ) -> Result<salesforce_core_v1::ByteStream, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_ingest_job_unprocessed_results(job_id)
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(response.into_inner())
    }

    /// Retrieves information about all ingest jobs.
    ///
    /// This method supports filtering and pagination.
    ///
    /// # Arguments
    ///
    /// * `is_pk_chunking_enabled` - Optional filter for jobs with PK chunking enabled
    /// * `job_type` - Optional filter by job type
    /// * `query_locator` - Optional pagination locator from a previous response's nextRecordsUrl
    ///
    /// # Returns
    ///
    /// A list of ingest jobs matching the filter criteria.
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
    /// let ingest_client = bulk_client.ingest();
    ///
    /// let jobs = ingest_client.get_all_jobs(None, None, None).await?;
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
        query_locator: Option<&str>,
    ) -> Result<salesforce_core_v1::types::GetAllIngestJobsResponse, Error> {
        let http_client = self.build_http_client().await?;
        let base_url = self.bulk_client.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_all_ingest_jobs(is_pk_chunking_enabled, job_type, query_locator)
            .await
            .map_err(|source| Error::BulkApi { source })?;
        Ok(response.into_inner())
    }
}

/// Error type for bulk ingest operations.
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
