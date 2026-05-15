use crate::{
    auth_engine::{AuthEngine, ExtractedState, is_csrf_like},
    ca::CertificateAuthority,
    capture::{CaptureOptions, CaptureStore},
    error::DothoundResult,
    proxy::ProxyServer,
    report,
    types::parse_login_endpoint,
};
use serde::{Deserialize, Serialize};
use std::{env, sync::Mutex};
use tokio::sync::oneshot;

// ── JSON protocol types ────────────────────────────────────────────

/// Command sent from the Go wrapper to DotHound via stdin.
#[derive(Debug, Deserialize)]
#[serde(tag = "command")]
pub enum StdinCommand {
    /// Execute a headless login capture workflow.
    #[serde(rename = "capture_login")]
    CaptureLogin {
        target_url: String,
        username: String,
        password: String,
        #[serde(default)]
        options: StdinOptions,
    },
    /// Start the MITM proxy in daemon mode and return the proxy address.
    #[serde(rename = "start_proxy")]
    StartProxy {
        #[serde(default)]
        options: StdinOptions,
    },
    /// Shut down the daemon proxy and write the workflow graph.
    #[serde(rename = "shutdown")]
    Shutdown,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct StdinOptions {
    #[serde(default = "default_include_secrets")]
    pub include_secrets: bool,
    #[serde(default = "default_max_body")]
    pub max_body_capture_bytes: usize,
}

fn default_include_secrets() -> bool {
    false
}
fn default_max_body() -> usize {
    64 * 1024
}

/// Response sent from DotHound to the Go wrapper via stdout.
#[derive(Debug, Serialize)]
pub struct StdinResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_cert_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<StdinSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for StdinResponse {
    fn default() -> Self {
        Self {
            status: "ok".to_owned(),
            workflow_path: None,
            html_path: None,
            proxy_url: None,
            ca_cert_pem: None,
            summary: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StdinSummary {
    pub total_exchanges: usize,
    pub http_exchanges: usize,
    pub https_tunnels: usize,
    pub session_cookies: Vec<String>,
    pub csrf_tokens: Vec<String>,
    pub auth_success: bool,
    pub redirect_chain: Vec<String>,
}

// ── Daemon state ───────────────────────────────────────────────────

static DAEMON_STATE: Mutex<Option<DaemonState>> = Mutex::new(None);

struct DaemonState {
    #[allow(dead_code)]
    proxy_url: String,
    #[allow(dead_code)]
    ca_cert_pem: String,
    capture_store: CaptureStore,
    shutdown_sender: Option<oneshot::Sender<()>>,
}

// ── Main stdin entry point ─────────────────────────────────────────

pub async fn run_stdin_mode() -> DothoundResult<()> {
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;

    let command: StdinCommand =
        serde_json::from_str(&input).map_err(|e| format!("Failed to parse stdin command: {e}"))?;

    let response = execute_command(command).await;
    let json = serde_json::to_string(&response)?;
    println!("{json}");

    if response.status == "error" {
        std::process::exit(1);
    }

    Ok(())
}

async fn execute_command(command: StdinCommand) -> StdinResponse {
    match command {
        StdinCommand::CaptureLogin {
            target_url,
            username,
            password,
            options,
        } => execute_capture_login(target_url, username, password, options).await,
        StdinCommand::StartProxy { options } => execute_start_proxy(options).await,
        StdinCommand::Shutdown => StdinResponse {
            status: "error".to_owned(),
            error: Some("Shutdown received without active proxy daemon".to_owned()),
            ..Default::default()
        },
    }
}

// ── Daemon proxy ───────────────────────────────────────────────────

pub async fn execute_start_proxy(options: StdinOptions) -> StdinResponse {
    let workspace = match env::current_dir() {
        Ok(w) => w,
        Err(e) => return err_resp(format!("Cannot determine working directory: {e}")),
    };

    let ca_dir = workspace.join(".dothound").join("ca");
    let ca = match CertificateAuthority::load_or_create(&ca_dir) {
        Ok(ca) => ca,
        Err(e) => return err_resp(format!("Failed to create CA: {e}")),
    };
    let ca_pem = ca.ca_cert_pem().to_owned();

    let capture_options =
        CaptureOptions::new(options.include_secrets, options.max_body_capture_bytes);
    let capture_store = CaptureStore::new("daemon-proxy".to_owned(), capture_options.clone());

    let proxy = match ProxyServer::bind(
        "127.0.0.1:0",
        capture_store.clone(),
        capture_options,
        ca.clone(),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return err_resp(format!("Failed to start proxy: {e}")),
    };

    let proxy_addr = match proxy.local_addr() {
        Ok(a) => a,
        Err(e) => return err_resp(format!("Failed to get proxy address: {e}")),
    };

    let proxy_url = format!("http://{proxy_addr}");
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    {
        let mut state = DAEMON_STATE.lock().unwrap();
        *state = Some(DaemonState {
            proxy_url: proxy_url.clone(),
            ca_cert_pem: ca_pem.clone(),
            capture_store: capture_store.clone(),
            shutdown_sender: Some(shutdown_sender),
        });
    }

    tokio::spawn(async move { proxy.run(shutdown_receiver).await });

    StdinResponse {
        status: "ok".to_owned(),
        proxy_url: Some(proxy_url),
        ca_cert_pem: Some(ca_pem),
        ..Default::default()
    }
}

pub async fn shutdown_daemon() -> DothoundResult<()> {
    let state = {
        let mut guard = DAEMON_STATE.lock().unwrap();
        guard.take()
    };

    let Some(state) = state else {
        return Err("No active daemon proxy to shut down".into());
    };

    if let Some(sender) = state.shutdown_sender {
        let _ = sender.send(());
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let workspace = env::current_dir()?;
    let captures_dir = workspace.join("captures");
    let (json_path, graph) = state.capture_store.write_json_capture(&captures_dir)?;

    let html_path = json_path.with_extension("html");
    if let Ok(file) = std::fs::File::create(&html_path) {
        let mut writer = std::io::BufWriter::new(file);
        let _ = report::write_html_report(&graph, &mut writer);
    }

    let response = StdinResponse {
        status: "ok".to_owned(),
        workflow_path: Some(json_path.to_string_lossy().to_string()),
        html_path: Some(html_path.to_string_lossy().to_string()),
        summary: Some(StdinSummary {
            total_exchanges: graph.summary.total_exchanges,
            http_exchanges: graph.summary.http_exchanges,
            https_tunnels: graph.summary.https_tunnels,
            session_cookies: Vec::new(),
            csrf_tokens: Vec::new(),
            auth_success: false,
            redirect_chain: Vec::new(),
        }),
        ..Default::default()
    };

    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

// ── Capture login workflow ─────────────────────────────────────────

async fn execute_capture_login(
    target_url: String,
    username: String,
    password: String,
    options: StdinOptions,
) -> StdinResponse {
    let endpoint = match parse_login_endpoint(&target_url) {
        Ok(ep) => ep,
        Err(e) => return err_resp(format!("Invalid login endpoint: {e}")),
    };

    let workspace = match env::current_dir() {
        Ok(w) => w,
        Err(e) => return err_resp(format!("Cannot determine working directory: {e}")),
    };

    let ca_dir = workspace.join(".dothound").join("ca");
    let ca = match CertificateAuthority::load_or_create(&ca_dir) {
        Ok(ca) => ca,
        Err(e) => return err_resp(format!("Failed to create CA: {e}")),
    };

    let capture_options =
        CaptureOptions::new(options.include_secrets, options.max_body_capture_bytes);
    let capture_store = CaptureStore::new(endpoint.to_string(), capture_options.clone());

    let proxy = match ProxyServer::bind(
        "127.0.0.1:0",
        capture_store.clone(),
        capture_options,
        ca.clone(),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return err_resp(format!("Failed to start proxy: {e}")),
    };

    let proxy_addr = match proxy.local_addr() {
        Ok(a) => a,
        Err(e) => return err_resp(format!("Failed to get proxy address: {e}")),
    };

    let proxy_url = format!("http://{proxy_addr}");
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let proxy_task = tokio::spawn(async move { proxy.run(shutdown_receiver).await });

    let auth_engine = match AuthEngine::new(&proxy_url, ca.ca_cert_pem()) {
        Ok(engine) => engine,
        Err(e) => {
            let _ = shutdown_sender.send(());
            let _ = proxy_task.await;
            return err_resp(format!("Failed to create auth engine: {e}"));
        }
    };

    let endpoint_str = endpoint.to_string();
    let workflow_result =
        perform_headless_login(&auth_engine, &endpoint_str, &username, &password).await;

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let _ = shutdown_sender.send(());
    let _ = proxy_task.await;

    let (auth_success, session_cookies, csrf_tokens, redirect_chain) = match &workflow_result {
        Ok(state) => (
            state.auth_success,
            state.session_cookies.clone(),
            state.csrf_tokens.clone(),
            state.redirect_chain.clone(),
        ),
        Err(_) => (false, Vec::new(), Vec::new(), Vec::new()),
    };

    let captures_dir = workspace.join("captures");
    let (json_path, graph) = match capture_store.write_json_capture(&captures_dir) {
        Ok((p, g)) => (p, g),
        Err(e) => return err_resp(format!("Failed to write capture: {e}")),
    };

    let html_path = json_path.with_extension("html");
    let html_written = std::fs::File::create(&html_path)
        .ok()
        .map(|file| {
            let mut writer = std::io::BufWriter::new(file);
            report::write_html_report(&graph, &mut writer).is_ok()
        })
        .unwrap_or(false);

    StdinResponse {
        status: "ok".to_owned(),
        workflow_path: Some(json_path.to_string_lossy().to_string()),
        html_path: if html_written {
            Some(html_path.to_string_lossy().to_string())
        } else {
            None
        },
        summary: Some(StdinSummary {
            total_exchanges: graph.summary.total_exchanges,
            http_exchanges: graph.summary.http_exchanges,
            https_tunnels: graph.summary.https_tunnels,
            session_cookies,
            csrf_tokens,
            auth_success,
            redirect_chain,
        }),
        error: workflow_result.as_ref().err().map(|e| e.to_string()),
        ..Default::default()
    }
}

fn err_resp(msg: String) -> StdinResponse {
    StdinResponse {
        status: "error".to_owned(),
        error: Some(msg),
        ..Default::default()
    }
}

// ── Workflow state tracking ────────────────────────────────────────

struct WorkflowState {
    auth_success: bool,
    session_cookies: Vec<String>,
    csrf_tokens: Vec<String>,
    redirect_chain: Vec<String>,
}

async fn perform_headless_login(
    engine: &AuthEngine,
    endpoint: &str,
    username: &str,
    password: &str,
) -> DothoundResult<WorkflowState> {
    let mut state = WorkflowState {
        auth_success: false,
        session_cookies: Vec::new(),
        csrf_tokens: Vec::new(),
        redirect_chain: Vec::new(),
    };

    let (response, extracted) = engine.get_and_extract(endpoint).await?;
    let status = response.status();
    state.auth_success = status.is_success();

    for (name, value) in &extracted.hidden_fields {
        if is_csrf_like(name) {
            state.csrf_tokens.push(format!("{name}={value}"));
        }
    }
    for (name, content) in &extracted.meta_tokens {
        state.csrf_tokens.push(format!("{name}={content}"));
    }
    for cookie_value in response.headers().get_all("set-cookie") {
        if let Ok(cookie_str) = cookie_value.to_str() {
            state.session_cookies.push(cookie_str.to_owned());
        }
    }

    let username_field = find_field_name(&extracted, &["username", "email", "user", "login"]);
    let password_field = find_field_name(&extracted, &["password", "passwd", "pass"]);
    let csrf_field = extracted
        .hidden_fields
        .iter()
        .find(|(name, _)| is_csrf_like(name));
    let action_url = determine_action_url(endpoint, &response);

    let mut form_fields: Vec<(&str, &str)> = Vec::new();
    if let Some((name, value)) = csrf_field {
        form_fields.push((name.as_str(), value.as_str()));
    }
    let user_field = username_field.unwrap_or("username");
    let pass_field = password_field.unwrap_or("password");
    form_fields.push((user_field, username));
    form_fields.push((pass_field, password));

    let post_response = engine.post_form(&action_url, &form_fields).await?;
    let post_status = post_response.status();
    state.auth_success = post_status.is_success() || post_status.is_redirection();
    for cookie_value in post_response.headers().get_all("set-cookie") {
        if let Ok(cookie_str) = cookie_value.to_str() {
            state.session_cookies.push(cookie_str.to_owned());
        }
    }

    let mut current_response = post_response;
    let mut current_url = action_url;
    for _ in 0..10 {
        if current_response.status().is_redirection() {
            if let Some(location) = current_response.headers().get("location") {
                let next_url = resolve_url(&current_url, location.to_str().unwrap_or(""));
                state.redirect_chain.push(next_url.clone());
                let next_response = engine.get(&next_url).await?;
                if next_response.status().is_success() {
                    state.auth_success = true;
                }
                for cookie_value in next_response.headers().get_all("set-cookie") {
                    if let Ok(cookie_str) = cookie_value.to_str() {
                        state.session_cookies.push(cookie_str.to_owned());
                    }
                }
                current_url = next_url;
                current_response = next_response;
                continue;
            }
        }
        break;
    }

    Ok(state)
}

// ── Helpers ────────────────────────────────────────────────────────

fn find_field_name<'a>(state: &'a ExtractedState, candidates: &[&'a str]) -> Option<&'a str> {
    for c in candidates {
        if state
            .hidden_fields
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(c))
        {
            return Some(c);
        }
    }
    None
}

fn determine_action_url(base_url: &str, response: &reqwest::Response) -> String {
    let url = response.url().to_string();
    if !url.is_empty() {
        url
    } else {
        base_url.to_owned()
    }
}

fn resolve_url(base: &str, target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        return target.to_owned();
    }
    if let Ok(base_url) = url::Url::parse(base) {
        if let Ok(resolved) = base_url.join(target) {
            return resolved.to_string();
        }
    }
    if target.starts_with('/') {
        if let Some(host_end) = base
            .find("://")
            .and_then(|i| base[i + 3..].find('/').map(|j| i + 3 + j))
        {
            format!("{}{}", &base[..host_end], target)
        } else {
            format!("{}{}", base.trim_end_matches('/'), target)
        }
    } else {
        format!("{}/{}", base.trim_end_matches('/'), target)
    }
}
