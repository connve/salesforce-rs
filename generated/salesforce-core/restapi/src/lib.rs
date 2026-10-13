include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Adds the per-call headers the client was built with to every request.
///
/// `reqwest` adds the `reqwest::Client`'s default headers only for names the
/// request doesn't carry yet, so a per-call header replaces the default
/// header of the same name. This impl on `Client` takes precedence over the
/// no-op hooks progenitor implements for `&Client`.
impl ClientHooks<reqwest::header::HeaderMap> for Client {
    async fn pre<E>(
        &self,
        request: &mut reqwest::Request,
        _info: &OperationInfo,
    ) -> Result<(), Error<E>> {
        let headers = request.headers_mut();
        for (name, value) in &self.inner {
            headers.append(name.clone(), value.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Accepts one connection, answers 500, and returns the raw request head.
    async fn capture_request(listener: TcpListener) -> String {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut head = Vec::new();
        let mut buf = [0; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        socket
            .write_all(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await
            .expect("write");
        String::from_utf8_lossy(&head).to_lowercase()
    }

    #[tokio::test]
    async fn per_call_headers_replace_defaults_of_the_same_name() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(capture_request(listener));

        let mut defaults = HeaderMap::new();
        defaults.insert("sforce-auto-assign", HeaderValue::from_static("TRUE"));
        defaults.insert(
            "sforce-call-options",
            HeaderValue::from_static("client=sdk"),
        );
        let http = reqwest::Client::builder()
            .default_headers(defaults)
            .build()
            .expect("reqwest client");

        let mut per_call = HeaderMap::new();
        per_call.insert("sforce-auto-assign", HeaderValue::from_static("FALSE"));

        let client = Client::new_with_client(&format!("http://{addr}"), http, per_call);
        let _ = client.get_sobject_basic_info("Account").await;

        let request = server.await.expect("server task");
        assert!(request.contains("sforce-auto-assign: false"), "{request}");
        assert!(!request.contains("sforce-auto-assign: true"), "{request}");
        assert!(
            request.contains("sforce-call-options: client=sdk"),
            "{request}"
        );
    }
}
