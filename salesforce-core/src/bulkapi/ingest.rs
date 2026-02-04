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
    /// use salesforce_core::bulkapi::IngestOperation;
    /// use salesforce_core_v1::types::CreateIngestJobRequest;
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
        let http_client = self.bulk_client.build_http_client().await.map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&self.bulk_client.base_url(), http_client);

        let response = client.create_ingest_job(request).await.map_err(|source| Error::BulkApi { source })?;
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
        let http_client = self.bulk_client.build_http_client().await.map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&self.bulk_client.base_url(), http_client);

        let response = client.get_ingest_job(job_id).await.map_err(|source| Error::BulkApi { source })?;
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
