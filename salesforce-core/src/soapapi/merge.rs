//! SObject merge operations via the Salesforce SOAP API.
//!
//! Merge is a SOAP-only operation that combines up to three records of the
//! same type into a single master record. The losing records are deleted and
//! their related records are reparented to the master.

use super::Client;
use crate::client;
use serde_json::Value;

/// Result of a successful merge operation.
#[derive(Debug, Clone)]
pub struct MergeResponse {
    /// Whether the merge operation succeeded.
    pub success: bool,
    /// IDs of the records that were merged (the victim records).
    pub merged_record_ids: Vec<String>,
    /// IDs of related records that were reparented to the master.
    pub updated_related_ids: Vec<String>,
}

/// Error type for SOAP merge operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication/client error from salesforce-core.
    #[error("Authentication error: {source}")]
    Auth {
        #[source]
        source: client::Error,
    },

    /// Network-level communication failure.
    #[error("Communication error: {source}")]
    Communication {
        #[source]
        source: reqwest::Error,
    },

    /// Error returned by the Salesforce SOAP API during a merge operation.
    #[error("Merge API error: {message}")]
    MergeApi { message: String },
}

impl Client {
    /// Merges up to three records into a single master record via the SOAP API.
    ///
    /// The losing records are deleted and their related records are reparented
    /// to the master. Field values can optionally be set on the master record
    /// as part of the merge. Supported SObject types: Account, Contact, Lead,
    /// and Individual.
    ///
    /// # Arguments
    ///
    /// * `sobject_type` - The API name of the SObject type (Account, Contact, Lead, or Individual).
    /// * `master_record_id` - The Salesforce ID of the master (winning) record.
    /// * `record_ids_to_merge` - IDs of records to merge into the master (one or two).
    /// * `master_field_overrides` - Optional field values to set on the master record during the merge.
    /// * `allow_duplicate_save` - When `true`, includes a `DuplicateRuleHeader` to bypass duplicate detection rules.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use salesforce_core::client::{self, Credentials};
    /// use salesforce_core::soapapi;
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
    /// let soap_client = soapapi::ClientBuilder::new(auth_client).build()?;
    ///
    /// let mut overrides = serde_json::Map::new();
    /// overrides.insert("BillingCity".to_string(), json!("San Francisco"));
    ///
    /// let result = soap_client
    ///     .merge(
    ///         "Account",
    ///         "001xx000003DGb2AAG",
    ///         &["001xx000003DGb3AAG"],
    ///         Some(&overrides),
    ///         true,
    ///     )
    ///     .await?;
    /// assert!(result.success);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all))]
    pub async fn merge(
        &self,
        sobject_type: impl AsRef<str>,
        master_record_id: impl AsRef<str>,
        record_ids_to_merge: &[impl AsRef<str>],
        master_field_overrides: Option<&serde_json::Map<String, Value>>,
        allow_duplicate_save: bool,
    ) -> Result<MergeResponse, Error> {
        let sobject_type = sobject_type.as_ref();
        let master_record_id = master_record_id.as_ref();

        let http_client = self.get_http_client().await.map_err(|e| match e {
            crate::http::Error::Auth { source } => Error::Auth { source },
            crate::http::Error::InvalidHeader | crate::http::Error::Lock => Error::Auth {
                source: client::Error::LockError,
            },
            crate::http::Error::Build { source } => Error::Communication { source },
        })?;

        let soap_url = self.soap_url().map_err(|source| Error::Auth { source })?;

        let mut field_elements = String::new();
        if let Some(fields) = master_field_overrides {
            for (name, value) in fields {
                let val_str = match value {
                    Value::String(s) => xml_escape(s),
                    Value::Null => String::new(),
                    other => xml_escape(&other.to_string()),
                };
                field_elements.push_str(&format!("<{name}>{val_str}</{name}>"));
            }
        }

        let merge_ids: String = record_ids_to_merge
            .iter()
            .map(|id| {
                format!(
                    "<recordToMergeIds>{}</recordToMergeIds>",
                    xml_escape(id.as_ref())
                )
            })
            .collect();

        let token = self
            .auth_client
            .access_token()
            .await
            .map_err(|source| Error::Auth { source })?;

        let duplicate_header = if allow_duplicate_save {
            "\n    <sf:DuplicateRuleHeader>\n      <sf:allowSave>true</sf:allowSave>\n    </sf:DuplicateRuleHeader>"
        } else {
            ""
        };

        let envelope = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:sf="urn:partner.soap.sforce.com"
                  xmlns:sfobj="urn:sobject.partner.soap.sforce.com">
  <soapenv:Header>
    <sf:SessionHeader>
      <sf:sessionId>{session_id}</sf:sessionId>
    </sf:SessionHeader>{duplicate_header}
  </soapenv:Header>
  <soapenv:Body>
    <sf:merge>
      <sf:request>
        <sf:masterRecord>
          <sfobj:type>{sobject_type}</sfobj:type>
          <sfobj:Id>{master_record_id}</sfobj:Id>
          {field_elements}
        </sf:masterRecord>
        {merge_ids}
      </sf:request>
    </sf:merge>
  </soapenv:Body>
</soapenv:Envelope>"#,
            session_id = xml_escape(&token),
        );

        let response = http_client
            .post(&soap_url)
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("SOAPAction", "merge")
            .body(envelope)
            .send()
            .await
            .map_err(|source| Error::Communication { source })?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|source| Error::Communication { source })?;

        if status.is_success() && body.contains("<success>true</success>") {
            let merged_ids = extract_xml_values(&body, "mergedRecordIds");
            let updated_related_ids = extract_xml_values(&body, "updatedRelatedIds");
            Ok(MergeResponse {
                success: true,
                merged_record_ids: merged_ids,
                updated_related_ids,
            })
        } else if let Some(msg) = extract_soap_fault(&body) {
            Err(Error::MergeApi { message: msg })
        } else if !status.is_success() {
            Err(Error::MergeApi {
                message: format!("SOAP request failed with HTTP status {status}"),
            })
        } else {
            let msg = extract_xml_value(&body, "message")
                .unwrap_or_else(|| "Unknown merge error".to_string());
            Err(Error::MergeApi { message: msg })
        }
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

fn extract_xml_values(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut results = Vec::new();
    let mut search_from = 0;
    while let Some(start_offset) = xml[search_from..].find(&open) {
        let start = search_from + start_offset + open.len();
        if let Some(end_offset) = xml[start..].find(&close) {
            results.push(xml[start..start + end_offset].to_string());
            search_from = start + end_offset + close.len();
        } else {
            break;
        }
    }
    results
}

fn extract_soap_fault(xml: &str) -> Option<String> {
    extract_xml_value(xml, "faultstring")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_escape_special_characters() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn test_extract_xml_value_found() {
        let xml = "<root><message>Hello World</message></root>";
        assert_eq!(
            extract_xml_value(xml, "message"),
            Some("Hello World".to_string())
        );
    }

    #[test]
    fn test_extract_xml_value_not_found() {
        let xml = "<root><other>value</other></root>";
        assert_eq!(extract_xml_value(xml, "message"), None);
    }

    #[test]
    fn test_extract_xml_values_multiple() {
        let xml = "<r><id>001</id><id>002</id><id>003</id></r>";
        assert_eq!(extract_xml_values(xml, "id"), vec!["001", "002", "003"]);
    }

    #[test]
    fn test_extract_xml_values_empty() {
        let xml = "<r><other>value</other></r>";
        let result: Vec<String> = extract_xml_values(xml, "id");
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_soap_fault() {
        let xml = r#"<soapenv:Envelope><soapenv:Body><soapenv:Fault>
            <faultstring>INVALID_FIELD: No such column</faultstring>
        </soapenv:Fault></soapenv:Body></soapenv:Envelope>"#;
        assert_eq!(
            extract_soap_fault(xml),
            Some("INVALID_FIELD: No such column".to_string())
        );
    }

    #[test]
    fn test_extract_soap_fault_none() {
        let xml = "<soapenv:Envelope><soapenv:Body><success>true</success></soapenv:Body></soapenv:Envelope>";
        assert_eq!(extract_soap_fault(xml), None);
    }
}
