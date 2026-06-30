//! Composite API operations for bulk record operations.
//!
//! The Composite API supports up to 200 records per request (2000 for the
//! retrieve operation). Each operation returns a request builder that accepts
//! optional Salesforce-specific headers via `.header()` / `.headers()`, then
//! is dispatched with `.send().await`.

use super::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use salesforce_core_restapi::types::{
    CompositeCollectionCreateRequest, CompositeCollectionCreateResponse,
    CompositeCollectionDeleteResponse, CompositeCollectionRetrieveRequest,
    CompositeCollectionUpdateRequest, CompositeCollectionUpdateResponse,
    CompositeCollectionUpsertRequest, CompositeCollectionUpsertResponse, CompositeTreeRequest,
    CompositeTreeResponse,
};
use salesforce_core_restapi::{Client as GeneratedClient, Error as GeneratedError};
use serde_json::Value;

/// Error type for Composite API operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication error.
    #[error("Authentication error: {source}")]
    Auth {
        /// The underlying authentication error.
        #[source]
        source: crate::client::Error,
    },

    /// Error from the Salesforce Composite API.
    #[error("Salesforce Composite API error: {source}")]
    CompositeApi {
        /// The underlying API error.
        #[source]
        source: Box<GeneratedError<salesforce_core_restapi::types::ErrorResponse>>,
    },

    /// Error serializing request data.
    #[error("Failed to serialize request: {source}")]
    Serde {
        /// The underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// Error building HTTP client.
    #[error("Failed to build HTTP client: {source}")]
    HttpClient {
        /// The underlying HTTP client error.
        #[source]
        source: crate::http::Error,
    },

    /// A request header is either reserved by the SDK (`Authorization`,
    /// `Content-Type`, `Accept`) or could not be converted into a valid
    /// `HeaderName` / `HeaderValue`.
    #[error("Invalid request header `{name}`")]
    InvalidHeader {
        /// The header name that was rejected.
        name: String,
    },
}

impl Error {
    /// Returns `true` if the error is transient and the operation could
    /// succeed if retried.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Auth { source } => source.is_retryable(),
            Error::CompositeApi { source } => source.is_retryable(),
            Error::HttpClient { source } => source.is_retryable(),
            Error::Serde { .. } | Error::InvalidHeader { .. } => false,
        }
    }
}

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
        .map_err(|source| Error::HttpClient { source })
}

fn generated(client: &Client, http_client: reqwest::Client) -> Result<GeneratedClient, Error> {
    let base_url = client.base_url().map_err(|source| Error::Auth { source })?;
    Ok(GeneratedClient::new_with_client(&base_url, http_client))
}

macro_rules! impl_header_methods {
    () => {
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
    };
}

/// Builder for [`Client::create_records`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct CreateRecords<'a> {
    client: &'a Client,
    request: &'a CompositeCollectionCreateRequest,
    headers: HeaderBag,
}

impl<'a> CreateRecords<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<CompositeCollectionCreateResponse, Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
        let response =
            gen.create_records(self.request)
                .await
                .map_err(|source| Error::CompositeApi {
                    source: Box::new(source),
                })?;
        Ok(response.into_inner())
    }
}

/// Builder for [`Client::get_records`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct GetRecords<'a> {
    client: &'a Client,
    sobject_type: String,
    request: &'a CompositeCollectionRetrieveRequest,
    headers: HeaderBag,
}

impl<'a> GetRecords<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<Vec<serde_json::Map<String, Value>>, Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
        let response = gen
            .get_records(&self.sobject_type, self.request)
            .await
            .map_err(|source| Error::CompositeApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

/// Builder for [`Client::update_records`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct UpdateRecords<'a> {
    client: &'a Client,
    request: &'a CompositeCollectionUpdateRequest,
    headers: HeaderBag,
}

impl<'a> UpdateRecords<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<CompositeCollectionUpdateResponse, Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
        let response =
            gen.update_records(self.request)
                .await
                .map_err(|source| Error::CompositeApi {
                    source: Box::new(source),
                })?;
        Ok(response.into_inner())
    }
}

/// Builder for [`Client::upsert_records`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct UpsertRecords<'a> {
    client: &'a Client,
    sobject_type: String,
    external_id_field: String,
    request: &'a CompositeCollectionUpsertRequest,
    headers: HeaderBag,
}

impl<'a> UpsertRecords<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<CompositeCollectionUpsertResponse, Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
        let response = gen
            .upsert_records(&self.sobject_type, &self.external_id_field, self.request)
            .await
            .map_err(|source| Error::CompositeApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

/// Builder for [`Client::delete_records`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct DeleteRecords<'a> {
    client: &'a Client,
    ids: String,
    all_or_none: Option<bool>,
    headers: HeaderBag,
}

impl<'a> DeleteRecords<'a> {
    impl_header_methods!();

    /// Sets the `allOrNone` flag: if `true`, the entire request is rolled
    /// back when any record fails to delete.
    pub fn all_or_none(mut self, all_or_none: bool) -> Self {
        self.all_or_none = Some(all_or_none);
        self
    }

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<CompositeCollectionDeleteResponse, Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
        let response = gen
            .delete_records(self.all_or_none, &self.ids)
            .await
            .map_err(|source| Error::CompositeApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

/// Builder for [`Client::create_record_tree`].
#[must_use = "request builders do nothing until `.send().await` is called"]
pub struct CreateRecordTree<'a> {
    client: &'a Client,
    sobject_type: String,
    request: &'a CompositeTreeRequest,
    headers: HeaderBag,
}

impl<'a> CreateRecordTree<'a> {
    impl_header_methods!();

    /// Dispatches the request.
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn send(self) -> Result<CompositeTreeResponse, Error> {
        let http_client = http_client_with(self.client, self.headers).await?;
        let gen = generated(self.client, http_client)?;
        let response = gen
            .create_record_tree(&self.sobject_type, self.request)
            .await
            .map_err(|source| Error::CompositeApi {
                source: Box::new(source),
            })?;
        Ok(response.into_inner())
    }
}

impl Client {
    /// Builds a request to create multiple records in a single round-trip
    /// (up to 200 records).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi::{
    ///     self, CompositeCollectionCreateRequest, CompositeRecordRequest,
    /// };
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
    /// use salesforce_core_restapi::types::{
    ///     CompositeRecordRequest, CompositeRecordRequestAttributes,
    /// };
    /// let mut account = CompositeRecordRequest {
    ///     attributes: CompositeRecordRequestAttributes {
    ///         type_: "Account".to_string(),
    ///         reference_id: None,
    ///     },
    ///     extra: serde_json::Map::new(),
    /// };
    /// account.extra.insert("Name".to_string(), json!("Acme"));
    /// let request = CompositeCollectionCreateRequest {
    ///     all_or_none: false,
    ///     records: vec![account],
    /// };
    ///
    /// let results = rest
    ///     .composite()
    ///     .create_records(&request)
    ///     .header("Sforce-Duplicate-Rule-Header", "allowSave=true")
    ///     .send()
    ///     .await?;
    /// # let _ = results;
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_records<'a>(
        &'a self,
        request: &'a CompositeCollectionCreateRequest,
    ) -> CreateRecords<'a> {
        CreateRecords {
            client: self,
            request,
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to retrieve multiple records by ID (up to 2000).
    pub fn get_records<'a>(
        &'a self,
        sobject_type: impl Into<String>,
        request: &'a CompositeCollectionRetrieveRequest,
    ) -> GetRecords<'a> {
        GetRecords {
            client: self,
            sobject_type: sobject_type.into(),
            request,
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to update multiple records (up to 200).
    pub fn update_records<'a>(
        &'a self,
        request: &'a CompositeCollectionUpdateRequest,
    ) -> UpdateRecords<'a> {
        UpdateRecords {
            client: self,
            request,
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to upsert multiple records by external ID (up to 200).
    pub fn upsert_records<'a>(
        &'a self,
        sobject_type: impl Into<String>,
        external_id_field: impl Into<String>,
        request: &'a CompositeCollectionUpsertRequest,
    ) -> UpsertRecords<'a> {
        UpsertRecords {
            client: self,
            sobject_type: sobject_type.into(),
            external_id_field: external_id_field.into(),
            request,
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to delete multiple records (up to 200) by
    /// comma-separated ID list.
    pub fn delete_records(&self, ids: impl Into<String>) -> DeleteRecords<'_> {
        DeleteRecords {
            client: self,
            ids: ids.into(),
            all_or_none: None,
            headers: HeaderBag::new(),
        }
    }

    /// Builds a request to create a tree of related records (up to 200 across
    /// all levels).
    pub fn create_record_tree<'a>(
        &'a self,
        sobject_type: impl Into<String>,
        request: &'a CompositeTreeRequest,
    ) -> CreateRecordTree<'a> {
        CreateRecordTree {
            client: self,
            sobject_type: sobject_type.into(),
            request,
            headers: HeaderBag::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_header_bag_accepts_sforce_headers() {
        let mut bag = HeaderBag::new();
        bag.add("Sforce-Duplicate-Rule-Header", "allowSave=true");
        let map = bag.finish().expect("valid headers");
        assert_eq!(map.len(), 1);
    }
}
