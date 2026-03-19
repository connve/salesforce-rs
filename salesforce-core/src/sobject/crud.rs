//! SObject CRUD operations implementation.

use super::Client as SObjectClient;
use crate::client;
use salesforce_core_v1::types::SObjectDescribe;
use salesforce_core_v1::{Client as GeneratedClient, Error as GeneratedError};
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
    ///
    /// This variant represents errors returned by Salesforce at the API level,
    /// such as HTTP 4xx/5xx responses with a structured error body.
    #[error("SObject API error: {source}")]
    SObjectApi {
        #[source]
        source: GeneratedError<salesforce_core_v1::types::ErrorResponse>,
    },

    /// Network-level communication failure.
    ///
    /// Covers connection refused, timeouts, TLS errors, HTTP client construction
    /// failures, and errors reading the response body.
    #[error("Communication error: {source}")]
    Communication {
        #[source]
        source: reqwest::Error,
    },

    /// Serialization/deserialization error for JSON data.
    #[error("Serialization error: {source}")]
    Serialization {
        #[source]
        source: serde_json::Error,
    },

    /// Data must be a JSON object for record operations.
    #[error("Expected JSON object for record data, got {actual_type}")]
    InvalidDataType { actual_type: String },
}

impl SObjectClient {
    /// Helper to build an HTTP client with authentication headers and connection pooling.
    async fn build_http_client(&self) -> Result<reqwest::Client, Error> {
        crate::http::build_http_client(
            self.auth_client().as_ref(),
            self.connect_timeout(),
            self.request_timeout(),
        )
        .await
        .map_err(|e| match e {
            crate::http::Error::Auth { source } => Error::Auth { source },
            crate::http::Error::InvalidHeader => Error::Auth {
                source: client::Error::LockError,
            },
            crate::http::Error::Build { source } => Error::Communication { source },
        })
    }

    /// Creates a new record of the specified SObject type.
    ///
    /// # Arguments
    ///
    /// * `sobject_type` - The API name of the SObject type (e.g., "Account", "Contact")
    /// * `data` - The field values for the new record as a JSON object
    ///
    /// # Returns
    ///
    /// The Salesforce ID of the created record.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::sobject;
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
    /// #         instance_url: "https://your-instance.salesforce.com".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let sobject_client = sobject::ClientBuilder::new(auth_client).build();
    ///
    /// let data = json!({
    ///     "Name": "Acme Corporation",
    ///     "Industry": "Technology",
    ///     "BillingCity": "San Francisco"
    /// });
    ///
    /// let record_id = sobject_client.create("Account", data).await?;
    /// println!("Created record: {}", record_id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create(
        &self,
        sobject_type: impl AsRef<str>,
        data: Value,
    ) -> Result<String, Error> {
        let sobject_type = sobject_type.as_ref();
        let http_client = self.build_http_client().await?;
        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        // Convert Value to Map<String, Value> as expected by the generated client
        let data_map = match data {
            Value::Object(map) => map,
            other => {
                return Err(Error::InvalidDataType {
                    actual_type: match other {
                        Value::Null => "null".to_string(),
                        Value::Bool(_) => "boolean".to_string(),
                        Value::Number(_) => "number".to_string(),
                        Value::String(_) => "string".to_string(),
                        Value::Array(_) => "array".to_string(),
                        Value::Object(_) => unreachable!(),
                    },
                })
            }
        };

        let response = client
            .create_record(sobject_type, &data_map)
            .await
            .map_err(|source| Error::SObjectApi { source })?;

        Ok(response.into_inner().id)
    }

    /// Retrieves a record by its Salesforce ID.
    ///
    /// # Arguments
    ///
    /// * `sobject_type` - The API name of the SObject type
    /// * `record_id` - The Salesforce ID of the record (15 or 18 characters)
    /// * `fields` - Optional comma-separated list of fields to retrieve. If None, all fields are returned.
    ///
    /// # Returns
    ///
    /// The record data as a JSON object.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::sobject;
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
    /// let sobject_client = sobject::ClientBuilder::new(auth_client).build();
    ///
    /// // Get all fields
    /// let record = sobject_client.get("Account", "001xx000003DGb2AAG", None).await?;
    ///
    /// // Get specific fields
    /// let record = sobject_client.get(
    ///     "Account",
    ///     "001xx000003DGb2AAG",
    ///     Some("Id,Name,Industry")
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get(
        &self,
        sobject_type: impl AsRef<str>,
        record_id: impl AsRef<str>,
        fields: Option<&str>,
    ) -> Result<Value, Error> {
        let sobject_type = sobject_type.as_ref();
        let record_id = record_id.as_ref();
        let http_client = self.build_http_client().await?;
        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_record(sobject_type, record_id, fields)
            .await
            .map_err(|source| Error::SObjectApi { source })?;

        Ok(Value::Object(response.into_inner()))
    }

    /// Retrieves a record by an external ID field.
    ///
    /// # Arguments
    ///
    /// * `sobject_type` - The API name of the SObject type
    /// * `field_name` - The API name of the external ID field
    /// * `field_value` - The value of the external ID
    /// * `fields` - Optional comma-separated list of fields to retrieve
    ///
    /// # Returns
    ///
    /// The record data as a JSON object.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::sobject;
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
    /// let sobject_client = sobject::ClientBuilder::new(auth_client).build();
    ///
    /// let record = sobject_client.get_by_external_id(
    ///     "Account",
    ///     "ExternalId__c",
    ///     "EXT-12345",
    ///     None
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_by_external_id(
        &self,
        sobject_type: impl AsRef<str>,
        field_name: impl AsRef<str>,
        field_value: impl AsRef<str>,
        fields: Option<&str>,
    ) -> Result<Value, Error> {
        let sobject_type = sobject_type.as_ref();
        let field_name = field_name.as_ref();
        let field_value = field_value.as_ref();
        let http_client = self.build_http_client().await?;
        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .get_record_by_external_id(sobject_type, field_name, field_value, fields)
            .await
            .map_err(|source| Error::SObjectApi { source })?;

        Ok(Value::Object(response.into_inner()))
    }

    /// Updates an existing record.
    ///
    /// # Arguments
    ///
    /// * `sobject_type` - The API name of the SObject type
    /// * `record_id` - The Salesforce ID of the record to update
    /// * `data` - The field values to update as a JSON object
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::sobject;
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
    /// #         instance_url: "https://your-instance.salesforce.com".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let sobject_client = sobject::ClientBuilder::new(auth_client).build();
    ///
    /// let data = json!({
    ///     "Name": "Acme Corporation (Updated)",
    ///     "Industry": "Manufacturing"
    /// });
    ///
    /// sobject_client.update("Account", "001xx000003DGb2AAG", data).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update(
        &self,
        sobject_type: impl AsRef<str>,
        record_id: impl AsRef<str>,
        data: Value,
    ) -> Result<(), Error> {
        let sobject_type = sobject_type.as_ref();
        let record_id = record_id.as_ref();
        let http_client = self.build_http_client().await?;
        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        // Convert Value to Map<String, Value> as expected by the generated client
        let data_map = match data {
            Value::Object(map) => map,
            other => {
                return Err(Error::InvalidDataType {
                    actual_type: match other {
                        Value::Null => "null".to_string(),
                        Value::Bool(_) => "boolean".to_string(),
                        Value::Number(_) => "number".to_string(),
                        Value::String(_) => "string".to_string(),
                        Value::Array(_) => "array".to_string(),
                        Value::Object(_) => unreachable!(),
                    },
                })
            }
        };

        client
            .update_record(sobject_type, record_id, &data_map)
            .await
            .map_err(|source| Error::SObjectApi { source })?;

        Ok(())
    }

    /// Deletes a record.
    ///
    /// # Arguments
    ///
    /// * `sobject_type` - The API name of the SObject type
    /// * `record_id` - The Salesforce ID of the record to delete
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::sobject;
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
    /// let sobject_client = sobject::ClientBuilder::new(auth_client).build();
    ///
    /// sobject_client.delete("Account", "001xx000003DGb2AAG").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete(
        &self,
        sobject_type: impl AsRef<str>,
        record_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        let sobject_type = sobject_type.as_ref();
        let record_id = record_id.as_ref();
        let http_client = self.build_http_client().await?;
        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        client
            .delete_record(sobject_type, record_id)
            .await
            .map_err(|source| Error::SObjectApi { source })?;

        Ok(())
    }

    /// Retrieves metadata for the specified SObject type.
    ///
    /// This includes information about all fields, record types, and permissions.
    ///
    /// # Arguments
    ///
    /// * `sobject_type` - The API name of the SObject type
    ///
    /// # Returns
    ///
    /// Metadata about the SObject type including field definitions.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::sobject;
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
    /// let sobject_client = sobject::ClientBuilder::new(auth_client).build();
    ///
    /// let metadata = sobject_client.describe("Account").await?;
    /// println!("SObject: {} ({})", metadata.name, metadata.label);
    /// println!("Fields: {}", metadata.fields.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn describe(&self, sobject_type: impl AsRef<str>) -> Result<SObjectDescribe, Error> {
        let sobject_type = sobject_type.as_ref();
        let http_client = self.build_http_client().await?;
        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .describe_s_object(sobject_type)
            .await
            .map_err(|source| Error::SObjectApi { source })?;

        Ok(response.into_inner())
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

    #[tokio::test]
    async fn test_reqwest_error_conversion() {
        let reqwest_error = reqwest::Client::new()
            .get("http://invalid-url-that-does-not-exist.test")
            .send()
            .await
            .unwrap_err();

        let error = Error::Communication {
            source: reqwest_error,
        };

        assert!(matches!(error, Error::Communication { .. }));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn test_serde_error_conversion() {
        let bad_json = "{ invalid json }";
        let serde_error: serde_json::Error = serde_json::from_str::<Value>(bad_json).unwrap_err();

        let error = Error::Serialization {
            source: serde_error,
        };

        assert!(matches!(error, Error::Serialization { .. }));
        assert!(std::error::Error::source(&error).is_some());
    }
}
