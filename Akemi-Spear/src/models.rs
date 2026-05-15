// models.rs — JSON contract between Go (Akemi) and Rust (Akemi-Spear)
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =====================================================
// Input: sent by Go via stdin
// =====================================================

#[derive(Debug, Clone, Deserialize)]
pub struct ScanRequest {
    pub host: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default = "default_threads")]
    pub threads: u32,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub rate: f64, // 0 = unlimited
    #[serde(default = "default_retries")]
    pub retries: u32,
    #[serde(default = "default_true")]
    pub randomize: bool,
    #[serde(default)]
    pub syn_mode: bool,
    #[serde(default = "default_true")]
    pub banner_grab: bool,
    #[serde(default)]
    pub probe_templates_dir: String,
    #[serde(default)]
    pub resume_file: String,
    #[serde(default)]
    pub verbose: bool,
    /// Host discovery mode — skip port scanning, just check alive hosts
    #[serde(default)]
    pub no_port: bool,
}

fn default_threads() -> u32 {
    200
}
fn default_timeout() -> u64 {
    3000
}
fn default_retries() -> u32 {
    1
}
fn default_true() -> bool {
    true
}

// =====================================================
// Output: written as JSON to stdout
// =====================================================

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub hostname: String,
    pub ips: Vec<String>,
    /// Reverse DNS mapping: IP → PTR hostname
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub rdns: HashMap<String, String>,
    pub open_ports: Vec<PortResult>,
    pub scan_time_ms: u64,
    pub total_scanned: u32,
    pub scan_mode: String,
    /// OS family hint from TTL analysis (e.g. "Linux/macOS", "Windows")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_hint: Option<String>,
    /// Raw TTL value observed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub technology: Vec<String>,
    /// Structured technology matches with confidence scoring
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tech_matches: Vec<TechMatch>,
    /// Detected service name (e.g. "http", "ssh", "mysql")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Extracted version string (e.g. "OpenSSH 8.9p1", "nginx/1.24.0")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cn: Option<String>,
}

/// Structured technology detection match with confidence scoring.
#[derive(Debug, Clone, Serialize)]
pub struct TechMatch {
    pub name: String,
    pub category: String,
    pub confidence: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub evidence: String,
    /// Detection source: "builtin", "yaml-probe", or "http-header"
    pub source: String,
}

// =====================================================
// Host Discovery Result (for -np / --no-port mode)
// =====================================================

#[derive(Debug, Clone, Serialize)]
pub struct HostDiscoveryResult {
    pub total_hosts: u32,
    pub alive_hosts: Vec<AliveHost>,
    pub scan_time_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AliveHost {
    pub ip: String,
    pub alive: bool,
    /// Round-trip latency in milliseconds
    pub latency_ms: f64,
    /// Reverse DNS hostname (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdns: Option<String>,
    /// Method used to detect: "tcp-80", "tcp-443", etc.
    pub method: String,
}

// =====================================================
// Probe template (parsed from YAML)
// =====================================================

#[derive(Debug, Clone, Deserialize)]
pub struct ProbeTemplate {
    pub id: String,
    pub info: ProbeInfo,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub probe_string: String,
    pub matchers: Option<ProbeMatchers>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProbeInfo {
    pub name: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    #[allow(dead_code)] // Reserved for future report enrichment
    pub description: String,
    #[serde(default)]
    #[allow(dead_code)] // Reserved for future tag-based filtering
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProbeMatchers {
    #[serde(default)]
    pub banner_patterns: Vec<String>,
}

fn default_protocol() -> String {
    "http".to_string()
}

// =====================================================
// Resume state
// =====================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanState {
    pub host: String,
    pub scanned_ports: Vec<u16>,
    pub open_ports: Vec<u16>,
    pub timestamp: String,
}
