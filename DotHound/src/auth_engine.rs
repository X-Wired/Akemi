use scraper::{Html, Selector};
use std::io;

/// Represents tokens and secrets extracted from a login page.
#[derive(Debug, Clone, Default)]
pub struct ExtractedState {
    /// Hidden form fields that look like CSRF tokens, nonces, etc.
    pub hidden_fields: Vec<(String, String)>,
    /// Meta tags containing CSRF tokens.
    pub meta_tokens: Vec<(String, String)>,
    /// All cookies set during the flow.
    #[allow(dead_code)]
    pub cookies: Vec<(String, String)>,
}

/// Headless authentication engine that drives the login workflow through
/// the DotHound proxy, replacing the manual browser step.
pub struct AuthEngine {
    /// reqwest HTTP client configured to route through the DotHound proxy
    /// and trust the DotHound CA certificate.
    client: reqwest::Client,
}

impl AuthEngine {
    /// Create a new engine.
    ///
    /// * `proxy_addr` – the SocketAddr of the running DotHound proxy,
    ///   e.g. `"http://127.0.0.1:9999"`.
    /// * `ca_pem` – PEM-encoded DotHound CA certificate so the client
    ///   trusts the proxy's MITM certificates.
    pub fn new(proxy_addr: &str, ca_pem: &str) -> io::Result<Self> {
        let proxy =
            reqwest::Proxy::all(proxy_addr).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let ca_cert = reqwest::tls::Certificate::from_pem(ca_pem.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let client = reqwest::Client::builder()
            .proxy(proxy)
            .add_root_certificate(ca_cert)
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none()) // we capture redirects ourselves
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self { client })
    }

    /// Fetch a URL (GET) and return the response body as text.
    pub async fn get(&self, url: &str) -> io::Result<reqwest::Response> {
        self.client
            .get(url)
            .send()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// POST form-encoded data to `url`.
    pub async fn post_form(
        &self,
        url: &str,
        fields: &[(&str, &str)],
    ) -> io::Result<reqwest::Response> {
        self.client
            .post(url)
            .form(fields)
            .send()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// GET a URL and extract CSRF tokens and other hidden form fields
    /// from its HTML body.
    pub async fn get_and_extract(
        &self,
        url: &str,
    ) -> io::Result<(reqwest::Response, ExtractedState)> {
        let response = self.get(url).await?;
        let body = response
            .text()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let state = extract_state(&body);

        // Re-build the response since we consumed the body.  We'll create
        // a synthetic response that still carries the original status/headers,
        // but callers that need the real response can use `get()` instead.
        let synthetic = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok((synthetic, state))
    }

    /// Return a reference to the underlying reqwest client (useful for
    /// custom requests).
    #[allow(dead_code)]
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

// ── HTML extraction helpers ────────────────────────────────────────

/// Parse an HTML page and return any hidden form fields and meta tokens
/// that look like CSRF / nonce values.
pub fn extract_state(html: &str) -> ExtractedState {
    let document = Html::parse_document(html);

    let input_sel = Selector::parse("input[type='hidden']").unwrap();
    let meta_sel = Selector::parse("meta").unwrap();

    let mut state = ExtractedState::default();

    // Hidden <input> fields
    for element in document.select(&input_sel) {
        if let (Some(name), Some(value)) =
            (element.value().attr("name"), element.value().attr("value"))
        {
            if is_csrf_like(name) {
                state
                    .hidden_fields
                    .push((name.to_owned(), value.to_owned()));
            }
        }
    }

    // <meta> tags
    for element in document.select(&meta_sel) {
        if let (Some(name), Some(content)) = (
            element.value().attr("name"),
            element.value().attr("content"),
        ) {
            if is_csrf_like(name) {
                state
                    .meta_tokens
                    .push((name.to_owned(), content.to_owned()));
            }
        }
    }

    state
}

/// Determine whether a form-field name looks like a CSRF token, nonce,
/// or other security-relevant value.
pub fn is_csrf_like(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "csrf",
        "xsrf",
        "token",
        "nonce",
        "_token",
        "authenticity_token",
        "request_token",
        "form_token",
        "session_token",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || lower.starts_with("csrf")
        || lower.starts_with("xsrf")
        || lower.ends_with("_token")
        || lower.ends_with("_csrf")
}
