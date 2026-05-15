use crate::{
    auth_engine::AuthEngine,
    ca::CertificateAuthority,
    capture::{CaptureOptions, CaptureStore},
    error::DothoundResult,
    proxy::ProxyServer,
    report,
    types::{LoginInput, parse_login_endpoint},
};
use std::{
    env,
    io::{self, Write},
};
use tokio::sync::oneshot;

pub async fn run() -> DothoundResult<()> {
    print_banner();

    let input = collect_login_input()?;
    let workspace = env::current_dir()?;
    let ca_dir = workspace.join(".dothound").join("ca");

    // ── 1. Generate the DotHound CA ───────────────────────────────
    let ca = CertificateAuthority::create(&ca_dir)?;
    println!(
        "DotHound CA ready (cert: {})",
        CertificateAuthority::cert_path(&ca_dir).display()
    );

    // ── 2. Start the capture proxy ─────────────────────────────────
    let capture_options = CaptureOptions::from_env();
    let capture_store = CaptureStore::new(input.endpoint().to_string(), capture_options.clone());
    let proxy = ProxyServer::bind(
        "127.0.0.1:0",
        capture_store.clone(),
        capture_options,
        ca.clone(),
    )
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let proxy_url = format!("http://{proxy_addr}");

    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let proxy_task = tokio::spawn(async move { proxy.run(shutdown_receiver).await });

    // ── 3. Build the headless auth engine ──────────────────────────
    let auth_engine = AuthEngine::new(&proxy_url, ca.ca_cert_pem())?;

    println!("Capture proxy listening on {proxy_url}");
    println!("Target: {}", input.safe_target());
    println!("Performing headless login workflow...");
    println!();

    // ── 4. Execute the login workflow ──────────────────────────────
    let endpoint = input.endpoint().to_string();
    let username = prompt_line("User")?;
    let password = rpassword::prompt_password("pass: ")?;

    perform_login_workflow(&auth_engine, &endpoint, &username, &password).await?;

    println!();
    println!("Login workflow complete. Shutting down proxy...");

    // ── 5. Graceful shutdown ───────────────────────────────────────
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let _ = shutdown_sender.send(());
    proxy_task.await??;

    let (json_path, graph) = capture_store.write_json_capture(workspace.join("captures"))?;
    println!("Saved JSON graph: {}", json_path.display());

    // ── 6. Generate HTML report ────────────────────────────────────
    let html_path = json_path.with_extension("html");
    let html_file = std::fs::File::create(&html_path)?;
    let mut writer = std::io::BufWriter::new(html_file);
    report::write_html_report(&graph, &mut writer)?;
    println!("Saved HTML report: {}", html_path.display());

    Ok(())
}

// ── login workflow ─────────────────────────────────────────────────

async fn perform_login_workflow(
    engine: &AuthEngine,
    endpoint: &str,
    username: &str,
    password: &str,
) -> DothoundResult<()> {
    // Step 1: GET the login page, extract CSRF tokens and hidden fields
    println!("→ Fetching login page...");
    let (response, state) = engine.get_and_extract(endpoint).await?;
    println!("  Status: {}", response.status());

    if !state.hidden_fields.is_empty() {
        println!("  Extracted hidden fields:");
        for (name, value) in &state.hidden_fields {
            let display_value = if value.len() > 40 {
                format!("{}...", &value[..40])
            } else {
                value.clone()
            };
            println!("    {name} = {display_value}");
        }
    }

    // Step 2: Build the form payload
    let username_field = find_field_name(&state, &["username", "email", "user", "login"]);
    let password_field = find_field_name(&state, &["password", "passwd", "pass"]);
    let csrf_field = state
        .hidden_fields
        .iter()
        .find(|(name, _)| crate::auth_engine::is_csrf_like(name));

    // Step 3: Determine the POST target
    let action_url = determine_action_url(endpoint, &response);
    println!("→ Submitting login to: {action_url}");

    // Build form fields
    let mut form_fields: Vec<(&str, &str)> = Vec::new();
    if let Some((name, value)) = csrf_field {
        form_fields.push((name.as_str(), value.as_str()));
    }
    let user_field = username_field.unwrap_or("username");
    let pass_field = password_field.unwrap_or("password");
    form_fields.push((user_field, username));
    form_fields.push((pass_field, password));

    println!("  Form fields:");
    for (name, value) in &form_fields {
        let display = if *name == pass_field { "***" } else { value };
        println!("    {name} = {display}");
    }

    // Step 4: POST the login
    let post_response = engine.post_form(&action_url, &form_fields).await?;
    println!("  Login response: {}", post_response.status());

    // Step 5: Follow redirects (up to 10)
    let mut current_response = post_response;
    let mut current_url = action_url;
    for _ in 0..10 {
        let status = current_response.status();
        if status.is_redirection() {
            if let Some(location) = current_response.headers().get("location") {
                let location_str = location.to_str().unwrap_or("");
                let next_url = resolve_url(&current_url, location_str);
                println!("→ Following redirect: {next_url}");
                let next_response = engine.get(&next_url).await?;
                println!("  Status: {}", next_response.status());
                current_url = next_url;
                current_response = next_response;
                continue;
            }
        }
        break;
    }

    Ok(())
}

// ── helpers ────────────────────────────────────────────────────────

fn find_field_name<'a>(
    state: &'a crate::auth_engine::ExtractedState,
    candidates: &[&'a str],
) -> Option<&'a str> {
    for candidate in candidates {
        if state
            .hidden_fields
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(candidate))
        {
            return Some(candidate);
        }
    }
    None
}

fn determine_action_url(base_url: &str, response: &reqwest::Response) -> String {
    let url = response.url().to_string();
    if !url.is_empty() {
        return url;
    }
    base_url.to_owned()
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

fn collect_login_input() -> DothoundResult<LoginInput> {
    let endpoint = parse_login_endpoint(&prompt_line("Login endpoint")?)?;
    Ok(LoginInput::new(endpoint))
}

fn prompt_line(label: &str) -> io::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;

    let mut value = String::new();
    io::stdin().read_line(&mut value)?;

    Ok(value.trim().to_owned())
}

pub fn print_banner() {
    println!("DotHound {}", env!("CARGO_PKG_VERSION"));
    println!("Headless login workflow capture with HTTPS MITM");
    println!();
}
