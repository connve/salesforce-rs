//! Composite API operations for bulk record operations.
//!
//! The Composite API allows you to:
//! - Create up to 200 records in a single request
//! - Retrieve up to 2000 records in a single request
//! - Update up to 200 records in a single request
//! - Upsert up to 200 records in a single request
//! - Delete up to 200 records in a single request
//! - Create record trees with parent-child relationships

use super::Client;
use salesforce_core_restapi::types::{
    CompositeCollectionCreateRequest, CompositeCollectionCreateResponse,
    CompositeCollectionRetrieveRequest, CompositeCollectionUpdateRequest,
    CompositeCollectionUpdateResponse, CompositeCollectionUpsertRequest,
    CompositeCollectionUpsertResponse, CompositeTreeRequest, CompositeTreeResponse,
};
use salesforce_core_restapi::{Client as GeneratedClient, Error as GeneratedError};
use serde_json::Value;

/// Error type for Composite API operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication error.
    #[error("authentication error")]
    Auth {
        /// The underlying authentication error.
        #[source]
        source: crate::client::Error,
    },

    /// Error from the Salesforce Composite API.
    #[error("Salesforce Composite API error")]
    CompositeApi {
        /// The underlying API error.
        #[source]
        source: GeneratedError<salesforce_core_restapi::types::ErrorResponse>,
    },

    /// Error serializing request data.
    #[error("failed to serialize request")]
    Serde {
        /// The underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// Error building HTTP client.
    #[error("failed to build HTTP client")]
    HttpClient {
        /// The underlying HTTP client error.
        #[source]
        source: crate::http::Error,
    },
}

impl Client {
    /// Creates multiple records in a single request (up to 200 records).
    ///
    /// Records can be of different SObject types. Each record must include an
    /// `attributes` object with a `type` field specifying the SObject type.
    ///
    /// # Arguments
    ///
    /// * `request` - The create request with records and `allOrNone` flag
    ///
    /// # Returns
    ///
    /// A vector of results, one for each record in the same order as the request.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi::{self, CompositeCollectionCreateRequest, CompositeRecordRequest};
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
    /// let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let request = CompositeCollectionCreateRequest {
    ///     all_or_none: false,
    ///     records: vec![
    ///         serde_json::from_value(json!({
    ///             "attributes": { "type": "Account" },
    ///             "Name": "Acme Corp",
    ///             "Industry": "Technology"
    ///         }))?,
    ///         serde_json::from_value(json!({
    ///             "attributes": { "type": "Contact" },
    ///             "FirstName": "John",
    ///             "LastName": "Doe"
    ///         }))?,
    ///     ],
    /// };
    ///
    /// let results = rest_client.composite().create_records(&request).await?;
    /// for result in results.iter() {
    ///     if result.success {
    ///         if let Some(id) = &result.id {
    ///             println!("Created record: {}", id);
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_records(
        &self,
        request: &CompositeCollectionCreateRequest,
    ) -> Result<CompositeCollectionCreateResponse, Error> {
        let http_client = self
            .get_http_client()
            .await
            .map_err(|source| Error::HttpClient { source })?;

        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .create_records(request)
            .await
            .map_err(|source| Error::CompositeApi { source })?;

        Ok(response.into_inner())
    }

    /// Retrieves multiple records by ID in a single request (up to 2000 IDs).
    ///
    /// All records must be of the same SObject type. You can optionally specify
    /// which fields to retrieve for each record.
    ///
    /// # Arguments
    ///
    /// * `sobject_type` - The API name of the SObject type
    /// * `request` - The retrieve request with IDs and optional fields
    ///
    /// # Returns
    ///
    /// A vector of records with the requested fields.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi::{self, CompositeCollectionRetrieveRequest};
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
    /// let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let request = CompositeCollectionRetrieveRequest {
    ///     ids: vec![
    ///         "001xx000003DGb2AAG".to_string(),
    ///         "001xx000003DGb3AAG".to_string(),
    ///     ],
    ///     fields: vec!["Id".to_string(), "Name".to_string(), "Industry".to_string()],
    /// };
    ///
    /// let records = rest_client.composite().get_records("Account", &request).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_records(
        &self,
        sobject_type: impl AsRef<str>,
        request: &CompositeCollectionRetrieveRequest,
    ) -> Result<Vec<serde_json::Map<String, Value>>, Error> {
        let http_client = self
            .get_http_client()
            .await
            .map_err(|source| Error::HttpClient { source })?;

        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_records(sobject_type.as_ref(), request)
            .await
            .map_err(|source| Error::CompositeApi { source })?;

        Ok(response.into_inner())
    }

    /// Updates multiple records in a single request (up to 200 records).
    ///
    /// Records can be of different SObject types. Each record must include an
    /// `attributes` object with a `type` field and an `id` field.
    ///
    /// # Arguments
    ///
    /// * `request` - The update request with records and `allOrNone` flag
    ///
    /// # Returns
    ///
    /// A vector of results, one for each record in the same order as the request.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi::{self, CompositeCollectionUpdateRequest};
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
    /// let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let request = CompositeCollectionUpdateRequest {
    ///     all_or_none: false,
    ///     records: vec![
    ///         serde_json::from_value(json!({
    ///             "attributes": { "type": "Account" },
    ///             "id": "001xx000003DGb2AAG",
    ///             "Industry": "Manufacturing"
    ///         }))?,
    ///     ],
    /// };
    ///
    /// let results = rest_client.composite().update_records(&request).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_records(
        &self,
        request: &CompositeCollectionUpdateRequest,
    ) -> Result<CompositeCollectionUpdateResponse, Error> {
        let http_client = self
            .get_http_client()
            .await
            .map_err(|source| Error::HttpClient { source })?;

        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .update_records(request)
            .await
            .map_err(|source| Error::CompositeApi { source })?;

        Ok(response.into_inner())
    }

    /// Upserts multiple records in a single request (up to 200 records).
    ///
    /// Creates new records or updates existing records based on an external ID field.
    /// All records must be of the same SObject type.
    ///
    /// # Arguments
    ///
    /// * `sobject_type` - The API name of the SObject type
    /// * `external_id_field` - The API name of the external ID field
    /// * `request` - The upsert request with records and `allOrNone` flag
    ///
    /// # Returns
    ///
    /// A vector of results indicating whether each record was created or updated.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi::{self, CompositeCollectionUpsertRequest};
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
    /// let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let request = CompositeCollectionUpsertRequest {
    ///     all_or_none: false,
    ///     records: vec![
    ///         serde_json::from_value(json!({
    ///             "attributes": { "type": "Account" },
    ///             "ExternalId__c": "EXT-001",
    ///             "Name": "Acme Corp"
    ///         }))?,
    ///     ],
    /// };
    ///
    /// let results = rest_client
    ///     .composite()
    ///     .upsert_records("Account", "ExternalId__c", &request)
    ///     .await?;
    ///
    /// for result in results.iter() {
    ///     if result.success {
    ///         if let Some(id) = &result.id {
    ///             if result.created {
    ///                 println!("Created record: {}", id);
    ///             } else {
    ///                 println!("Updated record: {}", id);
    ///             }
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn upsert_records(
        &self,
        sobject_type: impl AsRef<str>,
        external_id_field: impl AsRef<str>,
        request: &CompositeCollectionUpsertRequest,
    ) -> Result<CompositeCollectionUpsertResponse, Error> {
        let http_client = self
            .get_http_client()
            .await
            .map_err(|source| Error::HttpClient { source })?;

        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .upsert_records(sobject_type.as_ref(), external_id_field.as_ref(), request)
            .await
            .map_err(|source| Error::CompositeApi { source })?;

        Ok(response.into_inner())
    }

    /// Deletes multiple records in a single request (up to 200 records).
    ///
    /// All records must be of the same SObject type.
    ///
    /// # Arguments
    ///
    /// * `ids` - Comma-separated list of record IDs to delete
    /// * `all_or_none` - If true, rolls back entire request if any record fails
    ///
    /// # Returns
    ///
    /// A vector of results, one for each record in the same order as the IDs.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi;
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
    /// let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let ids = "001xx000003DGb2AAG,001xx000003DGb3AAG";
    /// let results = rest_client.composite().delete_records(ids, Some(false)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_records(
        &self,
        ids: impl AsRef<str>,
        all_or_none: Option<bool>,
    ) -> Result<salesforce_core_restapi::types::CompositeCollectionDeleteResponse, Error> {
        let http_client = self
            .get_http_client()
            .await
            .map_err(|source| Error::HttpClient { source })?;

        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .delete_records(all_or_none, ids.as_ref())
            .await
            .map_err(|source| Error::CompositeApi { source })?;

        Ok(response.into_inner())
    }

    /// Creates a tree of records with parent-child relationships in a single request.
    ///
    /// Up to 200 records total can be created across all levels of the tree.
    /// Each record must have a unique `referenceId` in its `attributes` object.
    ///
    /// # Arguments
    ///
    /// * `sobject_type` - The API name of the parent SObject type
    /// * `request` - The tree request with nested records
    ///
    /// # Returns
    ///
    /// A response indicating which records were created successfully.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi::{self, CompositeTreeRequest};
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
    /// let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let request = CompositeTreeRequest {
    ///     records: vec![
    ///         serde_json::from_value(json!({
    ///             "attributes": {
    ///                 "type": "Account",
    ///                 "referenceId": "ref1"
    ///             },
    ///             "Name": "Acme Corp",
    ///             "Contacts": {
    ///                 "records": [
    ///                     {
    ///                         "attributes": {
    ///                             "type": "Contact",
    ///                             "referenceId": "ref2"
    ///                         },
    ///                         "FirstName": "John",
    ///                         "LastName": "Doe"
    ///                     }
    ///                 ]
    ///             }
    ///         }))?,
    ///     ],
    /// };
    ///
    /// let response = rest_client.composite().create_record_tree("Account", &request).await?;
    /// if !response.has_errors {
    ///     println!("All records created successfully");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_record_tree(
        &self,
        sobject_type: impl AsRef<str>,
        request: &CompositeTreeRequest,
    ) -> Result<CompositeTreeResponse, Error> {
        let http_client = self
            .get_http_client()
            .await
            .map_err(|source| Error::HttpClient { source })?;

        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .create_record_tree(sobject_type.as_ref(), request)
            .await
            .map_err(|source| Error::CompositeApi { source })?;

        Ok(response.into_inner())
    }
}
