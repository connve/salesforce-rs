//! Flow invocation operations via the Custom Invocable Actions API.

use super::Client;
use crate::client;
use salesforce_core_restapi::types::{FlowInvokeRequest, FlowInvokeResponse};
use salesforce_core_restapi::{Client as GeneratedClient, Error as GeneratedError};
use serde_json::Value;

/// Error type for Flow invocation operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication/client error from salesforce-core.
    #[error("Authentication error: {source}")]
    Auth {
        #[source]
        source: client::Error,
    },

    /// Error from the generated REST API client.
    #[error("Flow API error: {source}")]
    FlowApi {
        #[source]
        source: GeneratedError<salesforce_core_restapi::types::ErrorResponse>,
    },

    /// Network-level communication failure.
    #[error("Communication error: {source}")]
    Communication {
        #[source]
        source: reqwest::Error,
    },

    /// Input variables must be a JSON object.
    #[error("Expected JSON object for flow inputs, got {actual_type}")]
    InvalidInputType { actual_type: String },
}

impl Error {
    /// Returns `true` if the error is transient and the operation could
    /// succeed if retried.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Auth { source } => source.is_retryable(),
            Error::FlowApi { source } => source.is_retryable(),
            Error::Communication { source } => source.is_timeout() || source.is_connect(),
            Error::InvalidInputType { .. } => false,
        }
    }
}

impl Client {
    /// Invokes an autolaunched flow with a single set of input variables.
    ///
    /// This is a convenience wrapper around [`invoke_flow_batch`](Self::invoke_flow_batch)
    /// that accepts a single JSON object of input variables.
    ///
    /// # Arguments
    ///
    /// * `flow_api_name` - The API name of the autolaunched flow
    /// * `inputs` - Input variables as a JSON object. Keys must match input
    ///   variable API names marked "Available for Input" in the flow.
    ///   Pass `json!({})` for flows with no input variables.
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
    /// #         instance_url: "https://your-instance.salesforce.com".to_string(),
    /// #         tenant_id: "...".to_string(),
    /// #     })
    /// #     .build()?
    /// #     .connect()
    /// #     .await?;
    /// let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let results = rest_client
    ///     .invoke_flow(
    ///         "Clone_Case_Record",
    ///         json!({
    ///             "CaseId": "5005i000009TQe0AAG",
    ///             "CloneCaseTeam": true,
    ///         }),
    ///     )
    ///     .await?;
    ///
    /// if results[0].is_success {
    ///     println!("Flow completed successfully");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn invoke_flow(
        &self,
        flow_api_name: impl AsRef<str>,
        inputs: Value,
    ) -> Result<FlowInvokeResponse, Error> {
        let input_map = match inputs {
            Value::Object(map) => map,
            other => {
                return Err(Error::InvalidInputType {
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

        let request = FlowInvokeRequest {
            inputs: vec![input_map.into_iter().collect()],
        };

        self.invoke_flow_batch(flow_api_name, &request).await
    }

    /// Invokes an autolaunched flow with multiple sets of input variables (batch).
    ///
    /// Each element in the `inputs` array launches a separate flow interview.
    /// The response contains one result per interview in the same order.
    ///
    /// # Arguments
    ///
    /// * `flow_api_name` - The API name of the autolaunched flow
    /// * `request` - The flow invocation request containing the `inputs` array
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::restapi::{self, FlowInvokeRequest};
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
    /// let rest_client = restapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let request = FlowInvokeRequest {
    ///     inputs: vec![
    ///         serde_json::from_value(json!({"CaseId": "5005i000009TQe0AAG"}))?,
    ///         serde_json::from_value(json!({"CaseId": "5005i000009TQe1BBH"}))?,
    ///     ],
    /// };
    ///
    /// let results = rest_client.invoke_flow_batch("Clone_Case_Record", &request).await?;
    /// for result in results.iter() {
    ///     println!(
    ///         "{}: success={}",
    ///         result.action_name, result.is_success
    ///     );
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn invoke_flow_batch(
        &self,
        flow_api_name: impl AsRef<str>,
        request: &FlowInvokeRequest,
    ) -> Result<FlowInvokeResponse, Error> {
        let flow_api_name = flow_api_name.as_ref();
        let http_client = self.get_http_client().await.map_err(|e| match e {
            crate::http::Error::Auth { source } => Error::Auth { source },
            crate::http::Error::InvalidHeader | crate::http::Error::Lock => Error::Auth {
                source: client::Error::LockError,
            },
            crate::http::Error::Build { source } => Error::Communication { source },
        })?;
        let base_url = self.base_url().map_err(|source| Error::Auth { source })?;
        let client = GeneratedClient::new_with_client(&base_url, http_client);

        let response = client
            .invoke_flow(flow_api_name, request)
            .await
            .map_err(|source| Error::FlowApi { source })?;

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
}
