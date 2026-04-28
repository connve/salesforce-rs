//! Integration tests for the Bulk API 2.0.

mod common;

use salesforce_core::bulkapi::ClientBuilder;
use salesforce_core_bulkapi::types::{CreateQueryJobRequest, QueryOperation};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn test_bulk_query_job_lifecycle() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;
    let query_client = client.query();

    let job = query_client
        .create_job(&CreateQueryJobRequest {
            operation: QueryOperation::Query,
            query: "SELECT Id, Name FROM Account LIMIT 5".to_string(),
            content_type: None,
            column_delimiter: None,
            line_ending: None,
        })
        .await?;
    assert!(!job.id.is_empty());

    let job_info = query_client.get_job(&job.id).await?;
    assert_eq!(job_info.id, job.id);

    query_client.abort_job(&job.id).await?;
    query_client.delete_job(&job.id).await?;

    Ok(())
}

#[tokio::test]
async fn test_bulk_query_get_all_jobs() -> Result {
    skip_if_no_credentials!();

    let auth = common::auth_client().await?;
    let client = ClientBuilder::new(auth).build()?;
    let query_client = client.query();

    // Validates the endpoint responds successfully.
    let _jobs = query_client.get_all_jobs(None, None, None, None).await?;

    Ok(())
}
