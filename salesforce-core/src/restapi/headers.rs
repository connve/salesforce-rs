//! Per-call request header plumbing shared by the REST request builders.

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

/// A header rejected by [`HeaderBag::finish`]. Each operation module maps
/// this into its own `Error::InvalidHeader`.
#[derive(Debug)]
pub(crate) struct InvalidHeader {
    pub(crate) name: String,
}

/// Accumulator for headers added to a request builder.
///
/// Header name/value conversion errors and forbidden-header detection are
/// surfaced from `.send()` so callers don't need to handle them at chain time.
pub(crate) struct HeaderBag {
    headers: HeaderMap,
    invalid: Option<String>,
}

impl HeaderBag {
    pub(crate) fn new() -> Self {
        Self {
            headers: HeaderMap::new(),
            invalid: None,
        }
    }

    pub(crate) fn from_map(headers: HeaderMap) -> Self {
        Self {
            headers,
            invalid: None,
        }
    }

    pub(crate) fn add<N, V>(&mut self, name: N, value: V)
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

    pub(crate) fn finish(self) -> Result<HeaderMap, InvalidHeader> {
        if let Some(name) = self.invalid {
            return Err(InvalidHeader { name });
        }
        if let Some(name) = super::client::forbidden_header(&self.headers) {
            return Err(InvalidHeader { name });
        }
        Ok(self.headers)
    }
}

/// Expands to the `.header()` / `.headers()` methods every request builder
/// exposes. The builder must hold its headers in a `headers: HeaderBag` field.
macro_rules! impl_header_methods {
    () => {
        /// Adds a single header to this request.
        pub fn header<N, V>(mut self, name: N, value: V) -> Self
        where
            N: TryInto<::reqwest::header::HeaderName>,
            V: TryInto<::reqwest::header::HeaderValue>,
        {
            self.headers.add(name, value);
            self
        }

        /// Replaces all per-call headers with `headers`.
        pub fn headers(mut self, headers: ::reqwest::header::HeaderMap) -> Self {
            self.headers = $crate::restapi::headers::HeaderBag::from_map(headers);
            self
        }
    };
}

pub(crate) use impl_header_methods;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_forbidden() {
        let mut bag = HeaderBag::new();
        bag.add("Authorization", "Bearer x");
        assert!(matches!(
            bag.finish(),
            Err(InvalidHeader { ref name }) if name == "authorization"
        ));
    }

    #[test]
    fn test_rejects_forbidden_in_replacement_map() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );
        assert!(matches!(
            HeaderBag::from_map(headers).finish(),
            Err(InvalidHeader { ref name }) if name == "content-type"
        ));
    }

    #[test]
    fn test_rejects_invalid_value() {
        let mut bag = HeaderBag::new();
        bag.add("Sforce-Auto-Assign", "bad\nvalue");
        assert!(matches!(
            bag.finish(),
            Err(InvalidHeader { ref name }) if name == "sforce-auto-assign"
        ));
    }

    #[test]
    fn test_rejects_invalid_name() {
        let mut bag = HeaderBag::new();
        bag.add("bad header", "x");
        assert!(matches!(
            bag.finish(),
            Err(InvalidHeader { ref name }) if name == "<invalid name>"
        ));
    }

    #[test]
    fn test_first_invalid_header_is_reported() {
        let mut bag = HeaderBag::new();
        bag.add("Sforce-Auto-Assign", "bad\nvalue");
        bag.add("Sforce-Mru", "bad\nvalue");
        assert!(matches!(
            bag.finish(),
            Err(InvalidHeader { ref name }) if name == "sforce-auto-assign"
        ));
    }

    #[test]
    fn test_accepts_sforce_headers() {
        let mut bag = HeaderBag::new();
        bag.add("Sforce-Duplicate-Rule-Header", "allowSave=true");
        bag.add("Sforce-Auto-Assign", "FALSE");
        bag.add("Sforce-Query-Options", "batchSize=500");
        let map = bag.finish().expect("valid headers");
        assert_eq!(map.len(), 3);
    }
}
