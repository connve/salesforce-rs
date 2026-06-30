//! SObject CRUD operations.
//!
//! Each operation returns a request builder that accepts optional
//! Salesforce-specific headers (`Sforce-Duplicate-Rule-Header`,
//! `Sforce-Auto-Assign`, …) via `.header()` / `.headers()`, then is dispatched
//! with `.send().await`.

use super::Client;
use crate::client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use salesforce_core_restapi::types::{CreateRecordResponse, SObjectBasicInfo, SObjectDescribe};
use salesforce_core_restapi::{Client as GeneratedClient, Error as GeneratedError};
use serde_json::Value;

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
        source: Box<GeneratedError<salesforce_core_restapi::types::ErrorResponse>>,
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

    /// A request header is either reserved by the SDK (`Authorization`,
    /// `Content-Type`, `Accept`) or could not be converted into a valid
    /// `HeaderName` / `HeaderValue`.
    #[error("Invalid request header `{name}`")]
    InvalidHeader { name: String },
}

impl Error {
    /// Returns `true` if the error is transient and the operation could
    /// succeed if retried.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Auth { source } => source.is_retryable(),
            Error::SObjectApi { source } => source.is_retryable(),
            Error::Communication { source } => source.is_timeout() || source.is_connect(),
            Error::InvalidDataType { .. } | Error::InvalidHeader { .. } => false,
        }
    }
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

fn unexpected(actual_type: &str) -> Error {
    Error::InvalidDataType {
        actual_type: actual_type.to_string(),
    }
}

/// Accumulator for headers added to a request builder.
///
/// Header name/value conversion errors and forbidden-header detection are
/// surfaced from `.send()` so callers don't need to handle them at chain time.
struct HeaderBag {
    headers: HeaderMap,
    invalid: Option<String>,
}

impl HeaderBag {
    fn new() -> Self {
        Self {
            headers: HeaderMap::new(),
            invalid: None,
        }
    }

    fn from_map(headers: HeaderMap) -> Self {
        Self {
            headers,
            invalid: None,
        }
    }

    fn add<N, V>(&mut self, name: N, value: V)
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        if self.invalid.is_some() {
            return;
        }
        match name.try_into() {
            Err(_) => self.invalid = Some("<invalid name>".to_string()),
            Ok(name) => match value.try_into() {
                Err(_) => self.invalid = Some(name.as_str().to_string()),
                Ok(value) => {
                    self.headers.append(name, value);
                }
            },
        }
    }

    fn finish(self) -> Result<HeaderMap, Error> {
        if let Some(name) = self.invalid {
            return Err(Error::InvalidHeader { name });
        }
        if let Some(name) = super::client::forbidden_header(&self.headers) {
            return Err(Error::InvalidHeader { name });
        }
        Ok(self.headers)
    }
}

async fn http_client_with(client: &Client, bag: HeaderBag) -> Result<reqwest::Client, Error> {
    let extra = bag.finish()?;
    client
        .get_http_client_with_extra(&extra)
        .await
        .map_err(map_http_error)
}

fn map_http_error(e: crate::http::Error) -> Error {
    match e {
        crate::http::Error::Auth { source } => Error::Auth { source },
        crate::http::Error::InvalidHeader | crate::http::Error::Lock => Error::Auth {
            source: client::Error::LockError,
        },
        crate::http::Error::Build { source } => Error::Communication { source },
    }
}

fn generated(client: &Client, http_client: reqwest::Client) -> Result<GeneratedClient, Error> {
    let base_url = client.base_url().map_err(|source| Error::Auth { source })?;
    Ok(GeneratedClient::new_with_client(&base_url, http_client))
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
    /// Adds a single header to this request.
    pub fn header<N, V>(mut self, name: N, value: V) -> Self
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        self.headers.add(name, value);
        self
    }

    /// Replaces all per-call headers with `headers`.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = HeaderBag::from_map(headers);
        self
    }

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<CreateRecordResponse, Error> {
        let data_map = require_object(self.data)?;
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
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

    /// Adds a single header to this request.
    pub fn header<N, V>(mut self, name: N, value: V) -> Self
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        self.headers.add(name, value);
        self
    }

    /// Replaces all per-call headers with `headers`.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = HeaderBag::from_map(headers);
        self
    }

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<Value, Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
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

    /// Adds a single header to this request.
    pub fn header<N, V>(mut self, name: N, value: V) -> Self
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        self.headers.add(name, value);
        self
    }

    /// Replaces all per-call headers with `headers`.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = HeaderBag::from_map(headers);
        self
    }

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<Value, Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
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
    /// Adds a single header to this request.
    pub fn header<N, V>(mut self, name: N, value: V) -> Self
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        self.headers.add(name, value);
        self
    }

    /// Replaces all per-call headers with `headers`.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = HeaderBag::from_map(headers);
        self
    }

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<(), Error> {
        let data_map = require_object(self.data)?;
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
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
    /// Adds a single header to this request.
    pub fn header<N, V>(mut self, name: N, value: V) -> Self
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        self.headers.add(name, value);
        self
    }

    /// Replaces all per-call headers with `headers`.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = HeaderBag::from_map(headers);
        self
    }

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<(), Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
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
    /// Adds a single header to this request.
    pub fn header<N, V>(mut self, name: N, value: V) -> Self
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        self.headers.add(name, value);
        self
    }

    /// Replaces all per-call headers with `headers`.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = HeaderBag::from_map(headers);
        self
    }

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<SObjectDescribe, Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
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
    /// Adds a single header to this request.
    pub fn header<N, V>(mut self, name: N, value: V) -> Self
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        self.headers.add(name, value);
        self
    }

    /// Replaces all per-call headers with `headers`.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = HeaderBag::from_map(headers);
        self
    }

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<SObjectBasicInfo, Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
        let response = gen
            .get_sobject_basic_info(&self.sobject_type)
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
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi;
    /// use serde_json::json;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let auth_client = client::Builder::new()
    /// #     .credentials(Credentials {
    /// #         client_id: "...".to_string(),
    /// #         client_secret: Some("...".to_string()),
    /// #         username: None,
    /// #         password: None,
    /// #         instance_url: "https://localhost".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
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
    fn test_require_object_rejects_array() {
        let result = require_object(serde_json::json!([]));
        assert!(matches!(
            result,
            Err(Error::InvalidDataType { ref actual_type }) if actual_type == "array"
        ));
    }

    #[test]
    fn test_require_object_accepts_object() {
        let result = require_object(serde_json::json!({"x": 1}));
        assert!(result.is_ok());
    }

    #[test]
    fn test_header_bag_rejects_forbidden() {
        let mut bag = HeaderBag::new();
        bag.add("Authorization", "Bearer x");
        assert!(matches!(
            bag.finish(),
            Err(Error::InvalidHeader { ref name }) if name == "authorization"
        ));
    }

    #[test]
    fn test_header_bag_rejects_invalid_value() {
        let mut bag = HeaderBag::new();
        bag.add("Sforce-Auto-Assign", "bad\nvalue");
        assert!(matches!(
            bag.finish(),
            Err(Error::InvalidHeader { ref name }) if name == "sforce-auto-assign"
        ));
    }

    #[test]
    fn test_header_bag_accepts_sforce_headers() {
        let mut bag = HeaderBag::new();
        bag.add("Sforce-Duplicate-Rule-Header", "allowSave=true");
        bag.add("Sforce-Auto-Assign", "FALSE");
        let map = bag.finish().expect("valid headers");
        assert_eq!(map.len(), 2);
    }
}
