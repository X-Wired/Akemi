// banner_grabber.rs — Phase 2: enrich open ports with banners, TLS info, and technology detection
use crate::models::{PortResult, ProbeTemplate};
use crate::tech_detect;
use log::{debug, warn};
use regex::Regex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Perform banner grabbing and technology detection on a single open port.
pub async fn grab_banner(
    ip: &str,
    port: u16,
    timeout_ms: u64,
    tcp_templates: &[ProbeTemplate],
) -> PortResult {
    let addr = format!("{}:{}", ip, port);
    let dur = Duration::from_millis(timeout_ms);

    let mut result = PortResult {
        port,
        state: "open".to_string(),
        banner: None,
        technology: Vec::new(),
        service: tech_detect::service_by_port(port).map(|s| s.to_string()),
        version: None,
        tls: false,
        tls_cn: None,
    };

    // --- Phase 1: Try TLS handshake first ---
    if let Ok(tls_result) = timeout(dur, try_tls_connect(&addr)).await {
        match tls_result {
            Ok((cn, banner_bytes)) => {
                result.tls = true;
                if let Some(cn) = cn {
                    result.tls_cn = Some(cn.clone());
                    if result.banner.is_none() {
                        result.banner = Some(format!("SSL Cert: CN={}", cn));
                    }
                }
                if !banner_bytes.is_empty() {
                    let raw = String::from_utf8_lossy(&banner_bytes).to_string();
                    process_banner(&mut result, &raw, port, tcp_templates);
                }
                if !result.technology.contains(&"TLS/SSL".to_string()) {
                    result.technology.push("TLS/SSL".to_string());
                }
                // Override service to https for TLS ports
                if result.service.as_deref() == Some("http") {
                    result.service = Some("https".to_string());
                }
                return result;
            }
            Err(_) => {
                debug!("TLS handshake failed for {}, trying plain TCP", addr);
            }
        }
    }

    // --- Phase 2: Plain TCP connect + probe ---
    let probe = find_probe_for_port(port, tcp_templates);

    match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            // Send probe if available
            let send_data = if let Some(ref p) = probe {
                unescape_probe_string(&p.probe_string)
            } else if is_web_port(port) {
                b"GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: Akemi-Spear/0.1\r\nAccept: */*\r\n\r\n".to_vec()
            } else {
                Vec::new()
            };

            if !send_data.is_empty() {
                let _ = stream.write_all(&send_data).await;
            }

            // Read response
            let mut buf = vec![0u8; 8192]; // Larger buffer for better detection
            match timeout(Duration::from_millis(timeout_ms.min(2000)), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) if n > 0 => {
                    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                    process_banner(&mut result, &raw, port, tcp_templates);
                }
                _ => {
                    if result.banner.is_none() {
                        result.banner = Some("<no banner>".to_string());
                    }
                }
            }
        }
        Ok(Err(e)) => {
            warn!("Plain TCP connect failed for {}: {}", addr, e);
            result.state = "filtered".to_string();
        }
        Err(_) => {
            result.state = "filtered".to_string();
        }
    }

    result
}

/// Process a raw banner string: extract first line, HTTP metadata, run tech detection,
/// extract version info, and match YAML probe templates.
fn process_banner(
    result: &mut PortResult,
    raw: &str,
    port: u16,
    tcp_templates: &[ProbeTemplate],
) {
    // First line as primary banner
    let first_line = raw.lines().next().unwrap_or("").trim().to_string();
    let mut banner = first_line.clone();

    // HTTP metadata extraction
    if raw.contains("HTTP/") {
        // Server header
        if let Some(cap) = Regex::new(r"(?i)Server:\s*(.*?)\r?\n")
            .ok()
            .and_then(|re| re.captures(raw))
        {
            let server = cap[1].trim().to_string();
            if !result.technology.contains(&server) {
                result.technology.push(server);
            }
        }

        // X-Powered-By header
        if let Some(cap) = Regex::new(r"(?i)X-Powered-By:\s*(.*?)\r?\n")
            .ok()
            .and_then(|re| re.captures(raw))
        {
            let powered_by = cap[1].trim().to_string();
            if !result.technology.contains(&powered_by) {
                result.technology.push(powered_by);
            }
        }

        // X-Generator header (CMS detection)
        if let Some(cap) = Regex::new(r"(?i)X-Generator:\s*(.*?)\r?\n")
            .ok()
            .and_then(|re| re.captures(raw))
        {
            let generator = cap[1].trim().to_string();
            if !result.technology.contains(&generator) {
                result.technology.push(generator);
            }
        }

        // Via header (proxy detection)
        if let Some(cap) = Regex::new(r"(?i)Via:\s*(.*?)\r?\n")
            .ok()
            .and_then(|re| re.captures(raw))
        {
            let via = format!("Via: {}", cap[1].trim());
            if !result.technology.contains(&via) {
                result.technology.push(via);
            }
        }

        // HTML title
        if let Some(cap) = Regex::new(r"(?i)<title>(.*?)</title>")
            .ok()
            .and_then(|re| re.captures(raw))
        {
            banner = format!("{} | Title: {}", banner, cap[1].trim());
        }
    }

    // --- Built-in tech detection (55 fingerprints) ---
    let (builtin_techs, detected_service, detected_version) =
        tech_detect::detect_technologies(raw);

    for tech in &builtin_techs {
        if !result.technology.contains(tech) {
            result.technology.push(tech.clone());
        }
    }

    // Set service if not already set from port-based detection
    if result.service.is_none() {
        if let Some(svc) = detected_service {
            result.service = Some(svc);
        }
    }

    // Set version if detected
    if result.version.is_none() {
        if let Some(ver) = detected_version {
            result.version = Some(ver);
        }
    }

    // --- Match against YAML probe templates ---
    for tmpl in tcp_templates {
        if tmpl.protocol != "tcp" {
            continue;
        }
        if let Some(ref matchers) = tmpl.matchers {
            for pattern_str in &matchers.banner_patterns {
                if let Ok(re) = Regex::new(pattern_str) {
                    if re.is_match(raw) {
                        let tech_name = tmpl.info.name.clone();
                        if !result.technology.contains(&tech_name) {
                            result.technology.push(tech_name);
                        }
                    }
                }
            }
        }
    }

    // Fallback service detection by port number
    if result.service.is_none() {
        result.service = tech_detect::service_by_port(port).map(|s| s.to_string());
    }

    result.banner = Some(banner);
}

/// Try a TLS connection. Returns (optional CN, bytes read after handshake).
async fn try_tls_connect(_addr: &str) -> Result<(Option<String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(not(feature = "tls-native"))]
    {
        let err = std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "tls-native feature not enabled",
        );
        return Err(Box::new(err));
    }

    #[cfg(feature = "tls-native")]
    {
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let connector = tokio_native_tls::TlsConnector::from(connector);

    let tcp_stream = TcpStream::connect(addr).await?;

    // Extract hostname from addr (before the colon)
    let host = addr.split(':').next().unwrap_or(addr);
    let mut tls_stream = connector.connect(host, tcp_stream).await?;

    // Extract certificate CN
    let cn = tls_stream
        .get_ref()
        .peer_certificate()
        .ok()
        .flatten()
        .and_then(|cert| {
            let der = cert.to_der().ok()?;
            extract_cn_from_der(&der)
        });

    // Try to read a banner
    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(Duration::from_millis(1500), tls_stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    Ok((cn, buf[..n].to_vec()))
    }
}

/// Simplified CN extraction from DER certificate.
#[cfg(feature = "tls-native")]
fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    let oid_cn = [0x55, 0x04, 0x03];
    for i in 0..der.len().saturating_sub(5) {
        if der[i] == oid_cn[0] && der[i + 1] == oid_cn[1] && der[i + 2] == oid_cn[2] {
            if i + 4 < der.len() {
                let tag = der[i + 3];
                if tag == 0x0C || tag == 0x13 || tag == 0x16 {
                    let len = der[i + 4] as usize;
                    if i + 5 + len <= der.len() {
                        return String::from_utf8(der[i + 5..i + 5 + len].to_vec()).ok();
                    }
                }
            }
        }
    }
    None
}

/// Find a probe template that targets a specific port.
fn find_probe_for_port(port: u16, templates: &[ProbeTemplate]) -> Option<ProbeTemplate> {
    for tmpl in templates {
        if tmpl.protocol != "tcp" || tmpl.probe_string.is_empty() {
            continue;
        }
        for port_spec in &tmpl.ports {
            if let Ok(p) = port_spec.parse::<u16>() {
                if p == port {
                    return Some(tmpl.clone());
                }
            }
            if let Some((start_s, end_s)) = port_spec.split_once('-') {
                if let (Ok(start), Ok(end)) = (start_s.parse::<u16>(), end_s.parse::<u16>()) {
                    if port >= start && port <= end {
                        return Some(tmpl.clone());
                    }
                }
            }
        }
    }
    None
}

/// Check if a port is commonly used for web services.
fn is_web_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443 | 8000 | 8888 | 3000 | 5000 | 9090)
}

/// Unescape probe strings from YAML (handle \r\n, etc.)
fn unescape_probe_string(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'r' => { result.push(b'\r'); i += 2; }
                b'n' => { result.push(b'\n'); i += 2; }
                b't' => { result.push(b'\t'); i += 2; }
                b'\\' => { result.push(b'\\'); i += 2; }
                _ => { result.push(bytes[i]); i += 1; }
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    result
}

/// Load TCP probe templates from a YAML directory.
pub fn load_tcp_templates(dir: &str) -> Vec<ProbeTemplate> {
    let mut templates = Vec::new();
    if dir.is_empty() {
        return templates;
    }

    // Support recursive directory scanning
    let entries = match read_dir_recursive(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("Error reading probe directory {}: {}", dir, e);
            return templates;
        }
    };

    for path in entries {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for doc in content.split("\n---") {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }
            match serde_yaml::from_str::<ProbeTemplate>(doc) {
                Ok(tmpl) if tmpl.protocol == "tcp" => {
                    templates.push(tmpl);
                }
                Ok(_) => {}
                Err(e) => {
                    debug!("Skipping template doc in {:?}: {}", path, e);
                }
            }
        }
    }

    templates
}

/// Recursively read all files from a directory.
fn read_dir_recursive(dir: &str) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Ok(sub_files) = read_dir_recursive(path.to_str().unwrap_or("")) {
                files.extend(sub_files);
            }
        } else {
            files.push(path);
        }
    }
    Ok(files)
}
