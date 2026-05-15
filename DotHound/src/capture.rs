use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct CaptureOptions {
    include_secrets: bool,
    pub max_body_capture_bytes: usize,
}

impl CaptureOptions {
    pub fn new(include_secrets: bool, max_body_capture_bytes: usize) -> Self {
        Self {
            include_secrets,
            max_body_capture_bytes,
        }
    }

    pub fn from_env() -> Self {
        let include_secrets = std::env::var("DOTHOUND_CAPTURE_SECRETS")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

        Self::new(include_secrets, 64 * 1024)
    }

    pub fn include_secrets(&self) -> bool {
        self.include_secrets
    }
}

#[derive(Debug, Clone)]
pub struct CaptureStore {
    graph: Arc<Mutex<CaptureGraph>>,
    sequence: Arc<AtomicU64>,
}

impl CaptureStore {
    pub fn new(start_url: String, options: CaptureOptions) -> Self {
        Self {
            graph: Arc::new(Mutex::new(CaptureGraph::new(start_url, &options))),
            sequence: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn next_exchange_id(&self) -> String {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
        format!("exchange-{sequence:04}")
    }

    pub fn record_exchange(&self, exchange: CapturedExchange) {
        let mut graph = self.graph.lock().expect("capture graph mutex poisoned");
        graph.record_exchange(exchange);
    }

    pub fn write_json_capture(
        &self,
        output_dir: impl AsRef<Path>,
    ) -> io::Result<(PathBuf, CaptureGraph)> {
        fs::create_dir_all(output_dir.as_ref())?;

        let mut graph = self
            .graph
            .lock()
            .expect("capture graph mutex poisoned")
            .clone();
        graph.completed_at_unix_ms = Some(unix_timestamp_millis());
        graph.summary.total_exchanges = graph.exchanges.len();
        graph.summary.http_exchanges = graph
            .exchanges
            .iter()
            .filter(|exchange| exchange.kind == ExchangeKind::Http)
            .count();
        graph.summary.https_tunnels = graph
            .exchanges
            .iter()
            .filter(|exchange| exchange.kind == ExchangeKind::HttpsTunnel)
            .count();

        let output_path = output_dir.as_ref().join(format!(
            "dothound-workflow-{}.json",
            unix_timestamp_millis()
        ));
        let output = fs::File::create(&output_path)?;
        serde_json::to_writer_pretty(output, &graph)?;

        Ok((output_path, graph))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureGraph {
    pub schema: &'static str,
    pub generated_by: &'static str,
    pub started_at_unix_ms: u128,
    pub completed_at_unix_ms: Option<u128>,
    pub start_url: String,
    pub redaction: RedactionPolicy,
    pub summary: CaptureSummary,
    pub nodes: Vec<WorkflowNode>,
    pub edges: Vec<WorkflowEdge>,
    pub exchanges: Vec<CapturedExchange>,
    #[serde(skip)]
    last_node_id: Option<String>,
}

impl CaptureGraph {
    fn new(start_url: String, options: &CaptureOptions) -> Self {
        Self {
            schema: "dothound.workflow_graph.v1",
            generated_by: concat!("Dothound/", env!("CARGO_PKG_VERSION")),
            started_at_unix_ms: unix_timestamp_millis(),
            completed_at_unix_ms: None,
            start_url,
            redaction: RedactionPolicy {
                mode: if options.include_secrets() {
                    "raw-sensitive-values"
                } else {
                    "sensitive-values-redacted"
                },
                sensitive_values_included: options.include_secrets(),
            },
            summary: CaptureSummary::default(),
            nodes: Vec::new(),
            edges: Vec::new(),
            exchanges: Vec::new(),
            last_node_id: None,
        }
    }

    fn record_exchange(&mut self, exchange: CapturedExchange) {
        let node_id = format!("node-{:04}", self.nodes.len() + 1);
        let label = format!("{} {}", exchange.request.method, exchange.request.target);

        if let Some(previous_node_id) = self.last_node_id.take() {
            self.edges.push(WorkflowEdge {
                from: previous_node_id,
                to: node_id.clone(),
                kind: "sequence",
            });
        }

        self.nodes.push(WorkflowNode {
            id: node_id.clone(),
            kind: exchange.kind,
            label,
            exchange_id: exchange.id.clone(),
        });
        self.last_node_id = Some(node_id);
        self.exchanges.push(exchange);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RedactionPolicy {
    pub mode: &'static str,
    pub sensitive_values_included: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CaptureSummary {
    pub total_exchanges: usize,
    pub http_exchanges: usize,
    pub https_tunnels: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkflowNode {
    pub id: String,
    pub kind: ExchangeKind,
    pub label: String,
    pub exchange_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkflowEdge {
    pub from: String,
    pub to: String,
    pub kind: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeKind {
    Http,
    HttpsTunnel,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapturedExchange {
    pub id: String,
    pub kind: ExchangeKind,
    pub started_at_unix_ms: u128,
    pub finished_at_unix_ms: u128,
    pub client_addr: String,
    pub request: CapturedRequest,
    pub response: Option<CapturedResponse>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapturedRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<CapturedHeader>,
    pub body: Option<CapturedBody>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapturedResponse {
    pub status_code: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<CapturedHeader>,
    pub body: Option<CapturedBody>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapturedHeader {
    pub name: String,
    pub value: String,
    pub sensitive: bool,
    pub value_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapturedBody {
    pub content_type: Option<String>,
    pub bytes_seen: usize,
    pub bytes_captured: usize,
    pub truncated: bool,
    pub text: Option<String>,
    pub sensitive: bool,
}

pub fn capture_headers(
    headers: &[(String, String)],
    options: &CaptureOptions,
) -> Vec<CapturedHeader> {
    headers
        .iter()
        .map(|(name, value)| {
            let sensitive = is_sensitive_name(name);
            let value_sha256 = sensitive.then(|| sha256_hex(value.as_bytes()));
            let value = if sensitive && !options.include_secrets() {
                "<redacted>".to_owned()
            } else {
                value.to_owned()
            };

            CapturedHeader {
                name: name.to_owned(),
                value,
                sensitive,
                value_sha256,
            }
        })
        .collect()
}

pub fn capture_body(
    headers: &[(String, String)],
    body: &[u8],
    options: &CaptureOptions,
) -> Option<CapturedBody> {
    if body.is_empty() {
        return None;
    }

    let content_type = header_value(headers, "content-type").map(str::to_owned);
    let truncated = body.len() > options.max_body_capture_bytes;
    let captured_body = &body[..body.len().min(options.max_body_capture_bytes)];
    let sensitive = content_type
        .as_deref()
        .map(content_type_can_contain_secrets)
        .unwrap_or(true);
    let text = body_text_preview(content_type.as_deref(), captured_body, sensitive, options);

    Some(CapturedBody {
        content_type,
        bytes_seen: body.len(),
        bytes_captured: captured_body.len(),
        truncated,
        text,
        sensitive,
    })
}

pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub fn content_length(headers: &[(String, String)]) -> Option<usize> {
    header_value(headers, "content-length")?.parse().ok()
}

pub fn unix_timestamp_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn body_text_preview(
    content_type: Option<&str>,
    body: &[u8],
    sensitive: bool,
    options: &CaptureOptions,
) -> Option<String> {
    let raw_text = String::from_utf8(body.to_vec()).ok()?;

    if options.include_secrets() {
        return Some(raw_text);
    }

    let content_type = content_type.unwrap_or_default().to_ascii_lowercase();

    if content_type.contains("application/json") {
        return serde_json::from_str::<serde_json::Value>(&raw_text)
            .map(|mut value| {
                redact_json_value(&mut value);
                value.to_string()
            })
            .ok()
            .or_else(|| Some("<redacted-json-body>".to_owned()));
    }

    if content_type.contains("application/x-www-form-urlencoded") {
        let pairs = url::form_urlencoded::parse(raw_text.as_bytes())
            .map(|(key, value)| {
                if is_sensitive_name(&key) {
                    format!("{key}=<redacted>")
                } else {
                    format!("{key}={value}")
                }
            })
            .collect::<Vec<_>>();

        return Some(pairs.join("&"));
    }

    if sensitive {
        Some("<redacted-body>".to_owned())
    } else {
        Some(raw_text)
    }
}

fn redact_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if is_sensitive_name(key) {
                    *value = serde_json::Value::String("<redacted>".to_owned());
                } else {
                    redact_json_value(value);
                }
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_json_value),
        _ => {}
    }
}

fn content_type_can_contain_secrets(content_type: &str) -> bool {
    let content_type = content_type.to_ascii_lowercase();
    content_type.contains("json")
        || content_type.contains("form")
        || content_type.contains("text")
        || content_type.contains("xml")
        || content_type.contains("javascript")
}

fn is_sensitive_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "authorization",
        "cookie",
        "set-cookie",
        "token",
        "csrf",
        "xsrf",
        "password",
        "passwd",
        "secret",
        "session",
        "credential",
        "api-key",
        "apikey",
        "jwt",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_headers_by_default() {
        let options = CaptureOptions::new(false, 1024);
        let headers = vec![("Authorization".to_owned(), "Bearer secret".to_owned())];

        let captured = capture_headers(&headers, &options);

        assert_eq!(captured[0].value, "<redacted>");
        assert!(captured[0].sensitive);
        assert!(captured[0].value_sha256.is_some());
    }

    #[test]
    fn redacts_sensitive_json_body_fields_by_default() {
        let options = CaptureOptions::new(false, 1024);
        let headers = vec![("content-type".to_owned(), "application/json".to_owned())];

        let captured = capture_body(
            &headers,
            br#"{"username":"alice","password":"secret","nested":{"csrf_token":"abc"}}"#,
            &options,
        )
        .unwrap();

        let text = captured.text.unwrap();
        assert!(text.contains(r#""username":"alice""#));
        assert!(text.contains(r#""password":"<redacted>""#));
        assert!(text.contains(r#""csrf_token":"<redacted>""#));
    }
}
