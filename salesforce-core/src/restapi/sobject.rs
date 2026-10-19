//! SObject CRUD operations.
//!
//! Each operation returns a request builder that accepts optional
//! Salesforce-specific headers (`Sforce-Duplicate-Rule-Header`,
//! `Sforce-Auto-Assign`, …) via `.header()` / `.headers()`, then is dispatched
//! with `.send().await`.

use super::headers::{impl_header_methods, HeaderBag, InvalidHeader};
use super::Client;
use crate::client;
use crate::http::{check_path_segments, InvalidPathSegment};
use chrono::{DateTime, Utc};
use salesforce_core_restapi::types::{
    CreateRecordResponse, ErrorResponse, GetDeletedRecordsResponse, SObjectBasicInfo,
    SObjectDescribe,
};
use salesforce_core_restapi::{Client as GeneratedClient, Error as GeneratedError};
use serde_json::Value;
use std::ops::Range;

/// Error type for SObject operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication/client error from salesforce-core.
    #[error("Authentication error: {source}")]
    Auth {
        #[source]
        source: client::Error,
    },

    /// Error from the generated SObject REST API client.
    #[error("SObject API error: {source}")]
    SObjectApi {
        #[source]
        source: Box<GeneratedError<ErrorResponse>>,
    },

    /// Network-level communication failure.
    #[error("Communication error: {source}")]
    Communication {
        #[source]
        source: reqwest::Error,
    },

    /// Data must be a JSON object for record operations.
    #[error("Expected JSON object for record data, got {actual_type}")]
    InvalidDataType { actual_type: String },

    /// A request header is either reserved (`Authorization`, `Content-Type`,
    /// `Accept`, `Content-Length`, `Transfer-Encoding`, `Host`) or could not be
    /// converted into a valid `HeaderName` / `HeaderValue`.
    #[error("Invalid request header `{name}`")]
    InvalidHeader { name: String },

    /// The requested time window ends at or before it starts. Salesforce
    /// rejects such a window, so it is caught before the request is sent.
    #[error("Time window must end after it starts, got start={start} end={end}")]
    InvalidTimeWindow {
        /// Inclusive start of the rejected window.
        start: DateTime<Utc>,
        /// Exclusive end of the rejected window.
        end: DateTime<Utc>,
    },

    /// An SObject type, record ID, or external ID used in the request path is
    /// empty, `.`, `..`, or contains control characters. Caught before the
    /// request is sent.
    #[error("Invalid path segment `{segment}`")]
    InvalidPathSegment {
        /// The rejected value.
        segment: String,
    },
}

impl Error {
    /// Returns `true` if the error is transient and the operation could
    /// succeed if retried.
    ///
    /// This only says the failure may be transient. Salesforce can have
    /// created the record before a timeout or 5xx reached you, so retrying
    /// `create` can create a duplicate. Where a duplicate is not acceptable,
    /// use [`Client::upsert_records`] with an external ID instead.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Auth { source } => source.is_retryable(),
            Error::SObjectApi { source } => source.is_retryable(),
            Error::Communication { source } => source.is_timeout() || source.is_connect(),
            Error::InvalidDataType { .. }
            | Error::InvalidHeader { .. }
            | Error::InvalidTimeWindow { .. }
            | Error::InvalidPathSegment { .. } => false,
        }
    }
}

fn require_path_segments(segments: &[&str]) -> Result<(), Error> {
    check_path_segments(segments)
        .map_err(|InvalidPathSegment { segment }| Error::InvalidPathSegment { segment })
}

fn require_object(data: Value) -> Result<serde_json::Map<String, Value>, Error> {
    match data {
        Value::Object(map) => Ok(map),
        Value::Null => Err(unexpected("null")),
        Value::Bool(_) => Err(unexpected("boolean")),
        Value::Number(_) => Err(unexpected("number")),
        Value::String(_) => Err(unexpected("string")),
        Value::Array(_) => Err(unexpected("array")),
    }
}

fn require_ordered_window(window: &Range<DateTime<Utc>>) -> Result<(), Error> {
    if window.end > window.start {
        Ok(())
    } else {
        Err(Error::InvalidTimeWindow {
            start: window.start,
            end: window.end,
        })
    }
}

fn unexpected(actual_type: &str) -> Error {
    Error::InvalidDataType {
        actual_type: actual_type.to_string(),
    }
}

/// The generated client for one request: the shared, cached HTTP client plus
/// the request's per-call headers.
async fn generated(client: &Client, headers: HeaderBag) -> Result<GeneratedClient, Error> {
    let headers = headers
        .finish()
        .map_err(|InvalidHeader { name }| Error::InvalidHeader { name })?;
    let http_client = client.get_http_client().await.map_err(|e| match e {
        crate::http::Error::Auth { source } => Error::Auth { source },
        crate::http::Error::Build { source } => Error::Communication { source },
    })?;
    let base_url = client.base_url().map_err(|source| Error::Auth { source })?;
    Ok(GeneratedClient::new_with_client(
        &base_url,
        http_client,
        headers,
    ))
}

/// Builder for [`Client::create`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct Create<'a> {
    client: &'a Client,
    sobject_type: String,
    data: Value,
    headers: HeaderBag,
}

impl<'a> Create<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<CreateRecordResponse, Error> {
        require_path_segments(&[&self.sobject_type])?;
        let data_map = require_object(self.data)?;
        let gen = generated(self.client, self.headers).await?;
        let response = gen
            .create_record(&self.sobject_type, &data_map)
            .await
            .map_err(|source| Error::SObjectApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

/// Builder for [`Client::get`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct Get<'a> {
    client: &'a Client,
    sobject_type: String,
    record_id: String,
    fields: Option<String>,
    headers: HeaderBag,
}

impl<'a> Get<'a> {
    /// Restricts the response to the given comma-separated field list.
    pub fn fields(mut self, fields: impl Into<String>) -> Self {
        self.fields = Some(fields.into());
        self
    }

    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<Value, Error> {
        require_path_segments(&[&self.sobject_type, &self.record_id])?;
        let gen = generated(self.client, self.headers).await?;
        let response = gen
            .get_record(&self.sobject_type, &self.record_id, self.fields.as_deref())
            .await
            .map_err(|source| Error::SObjectApi {
                source: Box::new(source),
            })?;
        Ok(Value::Object(response.into_inner()))
    }
}

/// Builder for [`Client::get_by_external_id`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct GetByExternalId<'a> {
    client: &'a Client,
    sobject_type: String,
    field_name: String,
    field_value: String,
    fields: Option<String>,
    headers: HeaderBag,
}

impl<'a> GetByExternalId<'a> {
    /// Restricts the response to the given comma-separated field list.
    pub fn fields(mut self, fields: impl Into<String>) -> Self {
        self.fields = Some(fields.into());
        self
    }

    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<Value, Error> {
        require_path_segments(&[&self.sobject_type, &self.field_name, &self.field_value])?;
        let gen = generated(self.client, self.headers).await?;
        let response = gen
            .get_record_by_external_id(
                &self.sobject_type,
                &self.field_name,
                &self.field_value,
                self.fields.as_deref(),
            )
            .await
            .map_err(|source| Error::SObjectApi {
                source: Box::new(source),
            })?;
        Ok(Value::Object(response.into_inner()))
    }
}

/// Builder for [`Client::update`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct Update<'a> {
    client: &'a Client,
    sobject_type: String,
    record_id: String,
    data: Value,
    headers: HeaderBag,
}

impl<'a> Update<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<(), Error> {
        require_path_segments(&[&self.sobject_type, &self.record_id])?;
        let data_map = require_object(self.data)?;
        let gen = generated(self.client, self.headers).await?;
        gen.update_record(&self.sobject_type, &self.record_id, &data_map)
            .await
            .map_err(|source| Error::SObjectApi {
                source: Box::new(source),
            })?;
        Ok(())
    }
}

/// Builder for [`Client::delete`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct Delete<'a> {
    client: &'a Client,
    sobject_type: String,
    record_id: String,
    headers: HeaderBag,
}

impl<'a> Delete<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<(), Error> {
        require_path_segments(&[&self.sobject_type, &self.record_id])?;
        let gen = generated(self.client, self.headers).await?;
        gen.delete_record(&self.sobject_type, &self.record_id)
            .await
            .map_err(|source| Error::SObjectApi {
                source: Box::new(source),
            })?;
        Ok(())
    }
}

/// Builder for [`Client::describe`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct Describe<'a> {
    client: &'a Client,
    sobject_type: String,
    headers: HeaderBag,
}

impl<'a> Describe<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<SObjectDescribe, Error> {
        require_path_segments(&[&self.sobject_type])?;
        let gen = generated(self.client, self.headers).await?;
        let response = gen
            .describe_sobject(&self.sobject_type)
            .await
            .map_err(|source| Error::SObjectApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

/// Builder for [`Client::basic_info`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct BasicInfo<'a> {
    client: &'a Client,
    sobject_type: String,
    headers: HeaderBag,
}

impl<'a> BasicInfo<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<SObjectBasicInfo, Error> {
        require_path_segments(&[&self.sobject_type])?;
        let gen = generated(self.client, self.headers).await?;
        let response = gen
            .get_sobject_basic_info(&self.sobject_type)
            .await
            .map_err(|source| Error::SObjectApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

/// Builder for [`Client::get_deleted`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct GetDeleted<'a> {
    client: &'a Client,
    sobject_type: String,
    window: Range<DateTime<Utc>>,
    headers: HeaderBag,
}

impl<'a> GetDeleted<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    ///
    /// Returns [`Error::InvalidTimeWindow`] without contacting Salesforce if
    /// the window is empty, i.e. its end is not after its start.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<GetDeletedRecordsResponse, Error> {
        require_path_segments(&[&self.sobject_type])?;
        require_ordered_window(&self.window)?;
        let gen = generated(self.client, self.headers).await?;
        // The generated signature orders query parameters alphabetically, so
        // `end` precedes `start`.
        let response = gen
            .get_deleted_records(&self.sobject_type, &self.window.end, &self.window.start)
            .await
            .map_err(|source| Error::SObjectApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

impl Client {
    /// Builds a request to create a new record of the specified SObject type.
    ///
    /// Add Salesforce request headers with [`Create::header`] / [`Create::headers`]
    /// and dispatch with `.send().await`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client;
    /// use salesforce_core::restapi;
    /// use serde_json::json;
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
    /// // Plain create:
    /// let resp = rest
    ///     .create("Account", json!({ "Name": "Acme" }))
    ///     .send()
    ///     .await?;
    ///
    /// // Create that overrides Salesforce duplicate-rule behaviour for this call:
    /// let resp = rest
    ///     .create("Account", json!({ "Name": "Acme" }))
    ///     .header("Sforce-Duplicate-Rule-Header", "allowSave=true")
    ///     .send()
    ///     .await?;
    /// # let _ = resp;
    /// # Ok(())
    /// # }
    /// ```
    pub fn create(&self, sobject_type: impl Into<String>, data: Value) -> Create<'_> {
        Create {
            client: self,
            sobject_type: sobject_type.into(),
            data,
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to retrieve a record by its Salesforce ID.
    pub fn get(&self, sobject_type: impl Into<String>, record_id: impl Into<String>) -> Get<'_> {
        Get {
            client: self,
            sobject_type: sobject_type.into(),
            record_id: record_id.into(),
            fields: None,
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to retrieve a record by an external ID field.
    pub fn get_by_external_id(
        &self,
        sobject_type: impl Into<String>,
        field_name: impl Into<String>,
        field_value: impl Into<String>,
    ) -> GetByExternalId<'_> {
        GetByExternalId {
            client: self,
            sobject_type: sobject_type.into(),
            field_name: field_name.into(),
            field_value: field_value.into(),
            fields: None,
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to update an existing record.
    pub fn update(
        &self,
        sobject_type: impl Into<String>,
        record_id: impl Into<String>,
        data: Value,
    ) -> Update<'_> {
        Update {
            client: self,
            sobject_type: sobject_type.into(),
            record_id: record_id.into(),
            data,
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to delete a record.
    pub fn delete(
        &self,
        sobject_type: impl Into<String>,
        record_id: impl Into<String>,
    ) -> Delete<'_> {
        Delete {
            client: self,
            sobject_type: sobject_type.into(),
            record_id: record_id.into(),
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to retrieve full metadata for an SObject type.
    pub fn describe(&self, sobject_type: impl Into<String>) -> Describe<'_> {
        Describe {
            client: self,
            sobject_type: sobject_type.into(),
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to retrieve basic info for an SObject type.
    pub fn basic_info(&self, sobject_type: impl Into<String>) -> BasicInfo<'_> {
        BasicInfo {
            client: self,
            sobject_type: sobject_type.into(),
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to retrieve the IDs and deletion datetimes of records
    /// of the specified SObject type that were deleted within `window`.
    ///
    /// The window is half-open, matching `Range` semantics: `start..end` covers
    /// deletions at or after `start` and strictly before `end`. An empty window
    /// (one whose end is not after its start) is rejected by
    /// [`GetDeleted::send`] as [`Error::InvalidTimeWindow`] without issuing a
    /// request.
    ///
    /// Salesforce enforces the remaining constraints server-side, and they are
    /// deliberately not replicated here because they vary by org and over time:
    ///
    /// - Deleted records are only visible while they remain in the Recycle Bin:
    ///   15 days by default, which an org can extend to 30. A `start` earlier
    ///   than the org's retention window is rejected with
    ///   `INVALID_REPLICATION_DATE`.
    /// - A window covering 600,000 or more deleted records is rejected with
    ///   `EXCEEDED_ID_LIMIT`; retry over a shorter window.
    /// - `end` cannot be in the future.
    ///
    /// The response's `earliest_date_available` reports how far back the org
    /// actually goes, so prefer reading it over hardcoding a retention figure.
    /// All three surface as [`Error::SObjectApi`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::chrono::{Duration, Utc};
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
    /// let end = Utc::now();
    /// let start = end - Duration::days(1);
    /// let deleted = rest.get_deleted("Account", start..end).send().await?;
    /// for record in &deleted.deleted_records {
    ///     println!("{} deleted at {}", record.id, record.deleted_date);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_deleted(
        &self,
        sobject_type: impl Into<String>,
        window: Range<DateTime<Utc>>,
    ) -> GetDeleted<'_> {
        GetDeleted {
            client: self,
            sobject_type: sobject_type.into(),
            window,
            headers: HeaderBag::new(),
        }
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

    #[test]
    fn test_window_rejects_end_before_start() {
        let end = Utc::now();
        let start = end + chrono::Duration::days(1);
        assert!(matches!(
            require_ordered_window(&(start..end)),
            Err(Error::InvalidTimeWindow { .. })
        ));
    }

    #[test]
    fn test_window_rejects_zero_length() {
        let at = Utc::now();
        assert!(matches!(
            require_ordered_window(&(at..at)),
            Err(Error::InvalidTimeWindow { .. })
        ));
    }

    #[test]
    fn test_window_accepts_ordered_range() {
        let end = Utc::now();
        let start = end - chrono::Duration::days(1);
        assert!(require_ordered_window(&(start..end)).is_ok());
    }

    #[test]
    fn test_require_object_rejects_array() {
        let result = require_object(serde_json::json!([]));
        assert!(matches!(
            result,
            Err(Error::InvalidDataType { ref actual_type }) if actual_type == "array"
        ));
    }

    #[test]
    fn test_path_segments_reject_dot_dot() {
        let error = require_path_segments(&["Account", ".."]).expect_err("rejected");
        assert!(matches!(
            error,
            Error::InvalidPathSegment { ref segment } if segment == ".."
        ));
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_require_object_accepts_object() {
        let result = require_object(serde_json::json!({"x": 1}));
        assert!(result.is_ok());
    }
}
