//! Offline tests for Bulk API 2.0 query results.
//!
//! Runs against a local `wiremock` server and needs no Salesforce org, so it
//! isn't `#[ignore]`d.

use futures_util::StreamExt;
use salesforce_core::bulkapi::query::QueryClient;
use salesforce_core::bulkapi::{ByteStream, ClientBuilder};
use salesforce_core::client;
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const JOB_ID: &str = "750xx0000000001AAA";

async fn query_client(server: &MockServer) -> Result<QueryClient> {
    Mock::given(method("POST"))
        .and(path("/services/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fake-token",
            "token_type": "Bearer",
        })))
        .mount(server)
        .await;

    let auth = client::Client::builder()
        .client_id("id")
        .client_secret("secret")
        .instance_url(server.uri())
        .build()?
        .connect()
        .await?;
    Ok(ClientBuilder::new(auth).build()?.query())
}

fn results_path() -> String {
    format!(
        "/services/data/v{}/jobs/query/{JOB_ID}/results",
        salesforce_core::DEFAULT_API_VERSION
    )
}

fn csv_page(csv: &str, locator: &str, records: u64) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("Sforce-Locator", locator)
        .insert_header("Sforce-NumberOfRecords", records.to_string().as_str())
        .set_body_raw(csv, "text/csv")
}

async fn read_body(mut body: ByteStream) -> Result<String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        bytes.extend_from_slice(&chunk?);
    }
    Ok(String::from_utf8(bytes)?)
}

#[tokio::test]
async fn get_results_exposes_locator_and_record_count() -> Result {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(results_path()))
        .and(header("authorization", "Bearer fake-token"))
        .and(query_param("maxRecords", "2"))
        .respond_with(csv_page("Id\n001A\n001B\n", "page2", 2))
        .expect(1)
        .mount(&server)
        .await;

    let page = query_client(&server)
        .await?
        .get_results(JOB_ID, std::num::NonZeroU64::new(2), None)
        .await?;

    assert_eq!(page.locator.as_deref(), Some("page2"));
    assert_eq!(page.number_of_records, Some(2));
    assert_eq!(read_body(page.body).await?, "Id\n001A\n001B\n");
    Ok(())
}

#[tokio::test]
async fn get_results_treats_null_locator_as_last_page() -> Result {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(results_path()))
        .respond_with(csv_page("Id\n001A\n", "null", 1))
        .mount(&server)
        .await;

    let page = query_client(&server)
        .await?
        .get_results(JOB_ID, None, None)
        .await?;

    assert_eq!(page.locator, None);
    Ok(())
}

#[tokio::test]
async fn result_pages_follows_locator_until_last_page() -> Result {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(results_path()))
        .and(query_param_is_missing("locator"))
        .respond_with(csv_page("Id\n001A\n", "page2", 1))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(results_path()))
        .and(query_param("locator", "page2"))
        .respond_with(csv_page("Id\n001B\n", "null", 1))
        .expect(1)
        .mount(&server)
        .await;

    let query_client = query_client(&server).await?;
    let mut pages = query_client.result_pages(JOB_ID, None);
    let mut bodies = Vec::new();
    while let Some(page) = pages.next_page().await {
        bodies.push(read_body(page?.body).await?);
    }

    assert_eq!(bodies, ["Id\n001A\n", "Id\n001B\n"]);
    assert!(pages.next_page().await.is_none());
    Ok(())
}

#[tokio::test]
async fn result_pages_retries_the_failed_page() -> Result {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(results_path()))
        .and(query_param_is_missing("locator"))
        .respond_with(csv_page("Id\n001A\n", "page2", 1))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(results_path()))
        .and(query_param("locator", "page2"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(results_path()))
        .and(query_param("locator", "page2"))
        .respond_with(csv_page("Id\n001B\n", "null", 1))
        .mount(&server)
        .await;

    let query_client = query_client(&server).await?;
    let mut pages = query_client.result_pages(JOB_ID, None);

    assert!(pages.next_page().await.transpose()?.is_some());
    assert!(matches!(pages.next_page().await, Some(Err(_))));
    let retried = pages.next_page().await.transpose()?;
    assert_eq!(
        read_body(retried.ok_or("missing page")?.body).await?,
        "Id\n001B\n"
    );
    assert!(pages.next_page().await.is_none());
    Ok(())
}
