//! Example of using Bulk API 2.0 Query and Ingest operations.
//!
//! This example demonstrates:
//!
//! Query Operations:
//! - Creating a query job
//! - Getting job information
//! - Retrieving query results
//! - Getting all query jobs
//! - Aborting and deleting jobs
//! - Using parallel result pages
//!
//! Ingest Operations:
//! - Creating an ingest job
//! - Uploading CSV data
//! - Marking upload as complete
//! - Monitoring job progress
//! - Retrieving successful, failed, and unprocessed results
//! - Managing ingest jobs

use futures_util::StreamExt;
use salesforce_core::bulkapi::Client as BulkClient;
use salesforce_core::client::{self, Credentials};
use salesforce_core_v1::types::{CreateQueryJobRequest, QueryOperation};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the Salesforce client
    let auth_client = client::Builder::new()
        .credentials(Credentials {
            client_id: std::env::var("SALESFORCE_CLIENT_ID")?,
            client_secret: Some(std::env::var("SALESFORCE_CLIENT_SECRET")?),
            username: None,
            password: None,
            instance_url: std::env::var("SALESFORCE_INSTANCE_URL")?,
            tenant_id: std::env::var("SALESFORCE_TENANT_ID")?,
        })
        .build()?
        .connect()
        .await?;

    let bulk_client = BulkClient::new(auth_client, salesforce_core::DEFAULT_API_VERSION);
    let query_client = bulk_client.query();

    info!("Creating a query job");
    let job = query_client
        .create_job(&CreateQueryJobRequest {
            operation: QueryOperation::Query,
            query: "SELECT Id, Name, Industry FROM Account LIMIT 100".to_string(),
            content_type: None,
            column_delimiter: None,
            line_ending: None,
        })
        .await?;
    info!("Created job: {}", job.id);

    info!("Getting job information");
    let job_info = query_client.get_job(&job.id).await?;
    info!("Job state: {:?}", job_info.state);

    info!("Waiting for job to complete");
    loop {
        let status = query_client.get_job(&job.id).await?;
        info!("Current state: {:?}", status.state);

        match status.state {
            salesforce_core_v1::types::JobState::JobComplete => {
                info!("Job completed");
                break;
            }
            salesforce_core_v1::types::JobState::Failed => {
                error!("Job failed");
                return Ok(());
            }
            salesforce_core_v1::types::JobState::Aborted => {
                error!("Job was aborted");
                return Ok(());
            }
            _ => {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }

    info!("Retrieving query results");
    let mut results = query_client.get_results(&job.id, Some(1000), None).await?;
    while let Some(chunk) = results.next().await {
        let _chunk = chunk?;
    }
    info!("Query results retrieved");

    info!("Getting parallel result pages");
    let result_pages = query_client.get_result_pages(&job.id, None).await?;
    info!("Found {} result pages", result_pages.result_pages.len());

    info!("Listing all query jobs");
    let all_jobs = query_client.get_all_jobs(None, None, None, None).await?;
    info!("Found {} jobs", all_jobs.records.len());

    info!("Creating a job to abort");
    let abort_job = query_client
        .create_job(&CreateQueryJobRequest {
            operation: QueryOperation::Query,
            query: "SELECT Id FROM Contact LIMIT 10".to_string(),
            content_type: None,
            column_delimiter: None,
            line_ending: None,
        })
        .await?;
    info!("Created job: {}", abort_job.id);

    info!("Aborting the job");
    let aborted = query_client.abort_job(&abort_job.id).await?;
    info!("Job state: {:?}", aborted.state);

    info!("Deleting the aborted job");
    query_client.delete_job(&abort_job.id).await?;
    info!("Job deleted successfully");

    let ingest_client = bulk_client.ingest();

    info!("Creating an ingest job");
    let ingest_job = ingest_client
        .create_job(&salesforce_core_v1::types::CreateIngestJobRequest {
            object: "Account".to_string(),
            external_id_field_name: None,
            content_type: Some(salesforce_core_v1::types::ContentType::Csv),
            operation: salesforce_core_v1::types::IngestOperation::Insert,
            line_ending: None,
            column_delimiter: None,
            assignment_rule_id: None,
        })
        .await?;
    info!("Created ingest job: {}", ingest_job.id);

    info!("Uploading CSV data");
    let csv_data = b"Name,Industry,Website\nAcme Corp,Technology,https://acme.example.com\nGlobus Inc,Manufacturing,https://globus.example.com";
    ingest_client.upload_data(&ingest_job.id, csv_data).await?;
    info!("CSV data uploaded");

    info!("Marking upload as complete");
    let completed_job = ingest_client.mark_upload_complete(&ingest_job.id).await?;
    info!("Job state: {:?}", completed_job.state);

    info!("Monitoring job progress");
    loop {
        let status = ingest_client.get_job(&ingest_job.id).await?;
        info!("Current state: {:?}", status.state);

        match status.state {
            salesforce_core_v1::types::JobState::JobComplete => {
                info!("Ingest job completed");
                break;
            }
            salesforce_core_v1::types::JobState::Failed => {
                error!("Job failed: {:?}", status.error_message);
                break;
            }
            salesforce_core_v1::types::JobState::Aborted => {
                error!("Job was aborted");
                break;
            }
            _ => {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }

    info!("Retrieving successful results");
    let mut successful_results = ingest_client.get_successful_results(&ingest_job.id).await?;
    while let Some(chunk) = successful_results.next().await {
        let _chunk = chunk?;
    }
    info!("Successful results retrieved");

    info!("Retrieving failed results");
    let mut failed_results = ingest_client.get_failed_results(&ingest_job.id).await?;
    while let Some(chunk) = failed_results.next().await {
        let _chunk = chunk?;
    }
    info!("Failed results retrieved");

    info!("Retrieving unprocessed results");
    let mut unprocessed_results = ingest_client
        .get_unprocessed_results(&ingest_job.id)
        .await?;
    while let Some(chunk) = unprocessed_results.next().await {
        let _chunk = chunk?;
    }
    info!("Unprocessed results retrieved");

    info!("Listing all ingest jobs");
    let all_ingest_jobs = ingest_client.get_all_jobs(None, None, None).await?;
    info!("Found {} ingest jobs", all_ingest_jobs.records.len());

    info!("Creating an ingest job to abort");
    let abort_ingest_job = ingest_client
        .create_job(&salesforce_core_v1::types::CreateIngestJobRequest {
            object: "Contact".to_string(),
            external_id_field_name: None,
            content_type: Some(salesforce_core_v1::types::ContentType::Csv),
            operation: salesforce_core_v1::types::IngestOperation::Insert,
            line_ending: None,
            column_delimiter: None,
            assignment_rule_id: None,
        })
        .await?;
    info!("Created job: {}", abort_ingest_job.id);

    info!("Aborting the ingest job");
    let aborted_ingest = ingest_client.abort_job(&abort_ingest_job.id).await?;
    info!("Job state: {:?}", aborted_ingest.state);

    info!("Deleting the aborted ingest job");
    ingest_client.delete_job(&abort_ingest_job.id).await?;
    info!("Job deleted successfully");

    info!("All examples completed successfully");

    Ok(())
}
