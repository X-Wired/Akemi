// banner_grabber.rs — Phase 2: enrich open ports with banners, TLS info, and technology detection
use crate::models::{PortResult, ProbeTemplate, TechMatch};
use crate::tech_detect;
use log::{debug, warn};
use regex::Regex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// Browser-like User-Agent for stealth probing.
const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

/// Pre-compiled HTTP header regexes (compiled once via OnceLock).
struct HttpRegexes {
    server: Regex,
    powered_by: Regex,
    generator: Regex,
    via: Regex,
    title: Regex,
}

fn http_regexes() -> &'static HttpRegexes {
    static REGEXES: OnceLock<HttpRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| HttpRegexes {
        server: Regex::new(r"(?i)Server:\s*(.*?)\r?\n").unwrap(),
        powered_by: Regex::new(r"(?i)X-Powered-By:\s*(.*?)\r?\n").unwrap(),
        generator: Regex::new(r"(?i)X-Generator:\s*(.*?)\r?\n").unwrap(),
        via: Regex::new(r"(?i)Via:\s*(.*?)\r?\n").unwrap(),
        title: Regex::new(r"(?i)<title>(.*?)</title>").unwrap(),
    })
}

/// Perform banner grabbing and technology detection on a single open port.
pub async fn grab_banner(
    host: &str,
    ip: &str,
    port: u16,
    timeout_ms: u64,
    tcp_templates: &[ProbeTemplate],
    tech_fingerprints: &[tech_detect::ExternalTechFingerprint],
) -> PortResult {
    let addr = format!("{}:{}", ip, port);
    let dur = Duration::from_millis(timeout_ms);

    let mut result = PortResult {
        port,
        state: "open".to_string(),
        banner: None,
        technology: Vec::new(),
        tech_matches: Vec::new(),
        service: tech_detect::service_by_port(port).map(|s| s.to_string()),
        version: None,
        tls: false,
        tls_cn: None,
    };

    // --- Phase 1: Try TLS handshake first ---
    if let Ok(tls_result) = timeout(dur, try_tls_connect(&addr, host, port)).await {
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
                    process_banner(&mut result, &raw, port, tcp_templates, tech_fingerprints);
                }
                if !result.technology.contains(&"TLS/SSL".to_string()) {
                    result.technology.push("TLS/SSL".to_string());
                    result.tech_matches.push(TechMatch {
                        name: "TLS/SSL".to_string(),
                        category: "transport".to_string(),
                        confidence: 1.0,
                        version: None,
                        evidence: "TLS handshake successful".to_string(),
                        source: "builtin".to_string(),
                    });
                }
                // Override service to https for TLS ports
                if result.service.as_deref() == Some("http") {
                    result.service = Some("https".to_string());
                }
                if let Some(hash) = fetch_favicon_hash(&addr, host, port, true, timeout_ms).await {
                    add_favicon_hash(&mut result, hash);
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
                format!(
                    "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\n\r\n",
                    host, DEFAULT_USER_AGENT
                )
                .into_bytes()
            } else {
                Vec::new()
            };

            if !send_data.is_empty() {
                let _ = stream.write_all(&send_data).await;
            }

            // Read response
            let mut buf = vec![0u8; 8192]; // Larger buffer for better detection
            match timeout(
                Duration::from_millis(timeout_ms.min(2000)),
                stream.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) if n > 0 => {
                    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                    process_banner(&mut result, &raw, port, tcp_templates, tech_fingerprints);
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

    if result.state == "open" {
        if let Some(hash) = fetch_favicon_hash(&addr, host, port, result.tls, timeout_ms).await {
            add_favicon_hash(&mut result, hash);
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
    tech_fingerprints: &[tech_detect::ExternalTechFingerprint],
) {
    let regexes = http_regexes();

    // First line as primary banner
    let first_line = raw.lines().next().unwrap_or("").trim().to_string();
    let mut banner = first_line.clone();

    // HTTP metadata extraction
    if raw.contains("HTTP/") {
        // Server header
        if let Some(cap) = regexes.server.captures(raw) {
            let server = cap[1].trim().to_string();
            if !result.technology.contains(&server) {
                result.technology.push(server.clone());
            }
            result.tech_matches.push(TechMatch {
                name: server.clone(),
                category: "http-header".to_string(),
                confidence: 0.95,
                version: None,
                evidence: format!("Server: {}", server),
                source: "http-header".to_string(),
            });
        }

        // X-Powered-By header
        if let Some(cap) = regexes.powered_by.captures(raw) {
            let powered_by = cap[1].trim().to_string();
            if !result.technology.contains(&powered_by) {
                result.technology.push(powered_by.clone());
            }
            result.tech_matches.push(TechMatch {
                name: powered_by.clone(),
                category: "http-header".to_string(),
                confidence: 0.90,
                version: None,
                evidence: format!("X-Powered-By: {}", powered_by),
                source: "http-header".to_string(),
            });
        }

        // X-Generator header (CMS detection)
        if let Some(cap) = regexes.generator.captures(raw) {
            let generator = cap[1].trim().to_string();
            if !result.technology.contains(&generator) {
                result.technology.push(generator.clone());
            }
            result.tech_matches.push(TechMatch {
                name: generator.clone(),
                category: "cms".to_string(),
                confidence: 0.85,
                version: None,
                evidence: format!("X-Generator: {}", generator),
                source: "http-header".to_string(),
            });
        }

        // Via header (proxy detection)
        if let Some(cap) = regexes.via.captures(raw) {
            let via = format!("Via: {}", cap[1].trim());
            if !result.technology.contains(&via) {
                result.technology.push(via.clone());
            }
            result.tech_matches.push(TechMatch {
                name: via.clone(),
                category: "proxy".to_string(),
                confidence: 0.80,
                version: None,
                evidence: via,
                source: "http-header".to_string(),
            });
        }

        // HTML title
        if let Some(cap) = regexes.title.captures(raw) {
            banner = format!("{} | Title: {}", banner, cap[1].trim());
        }
    }

    // --- Built-in tech detection (56 fingerprints, pre-compiled regexes) ---
    let (builtin_matches, detected_service, detected_version) =
        tech_detect::detect_technologies_with_custom(raw, tech_fingerprints);

    for tm in &builtin_matches {
        if !result.technology.contains(&tm.name) {
            result.technology.push(tm.name.clone());
        }
    }
    result.tech_matches.extend(builtin_matches);

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
                    if let Some(m) = re.find(raw) {
                        let tech_name = tmpl.info.name.clone();
                        if !result.technology.contains(&tech_name) {
                            result.technology.push(tech_name.clone());
                        }
                        // Use probe severity for confidence weighting
                        let confidence = match tmpl.info.severity.to_lowercase().as_str() {
                            "critical" | "high" => 0.95,
                            "medium" => 0.80,
                            "low" | "info" => 0.65,
                            _ => 0.70,
                        };
                        result.tech_matches.push(TechMatch {
                            name: tech_name,
                            category: "service".to_string(),
                            confidence,
                            version: None,
                            evidence: format!("[{}] matched: {}", tmpl.id, m.as_str()),
                            source: "yaml-probe".to_string(),
                        });
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

/// A certificate verifier that accepts any certificate.
#[derive(Debug)]
struct NoVerifier;
impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// Try a TLS connection. Returns (optional CN, bytes read after handshake).
async fn try_tls_connect(
    addr: &str,
    host: &str,
    port: u16,
) -> Result<(Option<String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

    // Enable SNI
    config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));
    let tcp_stream = TcpStream::connect(addr).await?;

    let sni_host = if host.trim().is_empty() {
        addr.split(':').next().unwrap_or(addr)
    } else {
        host
    };
    let server_name = ServerName::try_from(sni_host.to_string()).map_err(|_| "Invalid DNS name")?;

    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    // Extract certificate CN
    let mut cn = None;
    let (_, connection) = tls_stream.get_ref();
    if let Some(certs) = connection.peer_certificates() {
        if let Some(cert) = certs.first() {
            cn = extract_cn_from_der(cert);
        }
    }

    // Send a small HTTP request on web-ish TLS ports so headers, cookies, ALPN,
    // and body snippets become available for technology detection.
    if is_web_port(port) || port == 443 || port == 8443 || port == 9443 {
        let req = format!(
            "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\n\r\n",
            sni_host, DEFAULT_USER_AGENT
        );
        let _ = tls_stream.write_all(req.as_bytes()).await;
    }

    // Try to read a banner or HTTP response.
    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(Duration::from_millis(1500), tls_stream.read(&mut buf)).await
    {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    Ok((cn, buf[..n].to_vec()))
}

/// Load runtime technology fingerprint packs from YAML files.
pub fn load_tech_fingerprints(dir: &str) -> Vec<tech_detect::ExternalTechFingerprint> {
    tech_detect::load_fingerprint_packs(dir)
}

async fn fetch_favicon_hash(
    addr: &str,
    host: &str,
    port: u16,
    tls: bool,
    timeout_ms: u64,
) -> Option<String> {
    if !is_web_port(port) && port != 443 && port != 8443 && port != 9443 {
        return None;
    }
    let req = format!(
        "GET /favicon.ico HTTP/1.0\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: image/*,*/*\r\n\r\n",
        host, DEFAULT_USER_AGENT
    );
    let dur = Duration::from_millis(timeout_ms.min(2000));
    let mut bytes = Vec::new();

    if tls {
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .ok()?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let tcp_stream = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
        let server_name = ServerName::try_from(host.to_string()).ok()?;
        let mut stream = timeout(dur, connector.connect(server_name, tcp_stream))
            .await
            .ok()?
            .ok()?;
        let _ = stream.write_all(req.as_bytes()).await;
        let mut buf = vec![0u8; 8192];
        let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
        bytes.extend_from_slice(&buf[..n]);
    } else {
        let mut stream = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
        let _ = stream.write_all(req.as_bytes()).await;
        let mut buf = vec![0u8; 8192];
        let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
        bytes.extend_from_slice(&buf[..n]);
    }

    if bytes.is_empty() || !String::from_utf8_lossy(&bytes[..bytes.len().min(64)]).contains("200") {
        return None;
    }
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    Some(format!("{:016x}", hasher.finish()))
}

fn add_favicon_hash(result: &mut PortResult, hash: String) {
    result.tech_matches.push(TechMatch {
        name: "Favicon Hash".to_string(),
        category: "web-asset".to_string(),
        confidence: 0.30,
        version: None,
        evidence: format!("favicon_hash:{}", hash),
        source: "favicon".to_string(),
    });
}

/// Simplified CN extraction from DER certificate.
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
    matches!(
        port,
        80 | 443 | 8080 | 8443 | 8000 | 8888 | 3000 | 5000 | 9090
    )
}

/// Unescape probe strings from YAML (handle \r\n, etc.)
fn unescape_probe_string(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'r' => {
                    result.push(b'\r');
                    i += 2;
                }
                b'n' => {
                    result.push(b'\n');
                    i += 2;
                }
                b't' => {
                    result.push(b'\t');
                    i += 2;
                }
                b'\\' => {
                    result.push(b'\\');
                    i += 2;
                }
                _ => {
                    result.push(bytes[i]);
                    i += 1;
                }
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

    let mut loaded = 0;
    let mut skipped = 0;

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
                    loaded += 1;
                    templates.push(tmpl);
                }
                Ok(_) => {}
                Err(e) => {
                    skipped += 1;
                    debug!("Skipping template doc in {:?}: {}", path, e);
                }
            }
        }
    }

    if skipped > 0 {
        eprintln!(
            "[!] Loaded {} probes, {} skipped due to parse errors",
            loaded, skipped
        );
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
