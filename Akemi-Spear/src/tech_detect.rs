// tech_detect.rs — Built-in technology fingerprint database
//
// 56 signatures compiled into the binary for zero-config tech detection.
// Covers: web servers, frameworks, databases, proxies, CDN/cloud, CMS, WAFs,
// protocols (SSH, FTP, SMTP, DNS), and more.
//
// All regexes are compiled once via OnceLock for optimal performance.
// Each match carries a confidence score and evidence for downstream filtering.

use crate::models::TechMatch;
use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// A single technology fingerprint (static definition).
pub struct TechFingerprint {
    pub name: &'static str,
    pub category: &'static str,
    pub confidence: f32,
    /// Patterns to match against raw banner/response text.
    pub banner_patterns: &'static [&'static str],
    /// If set, also extract the version via this capture group pattern.
    pub version_pattern: Option<&'static str>,
    /// Service name to assign (e.g. "http", "ssh", "mysql")
    pub service: Option<&'static str>,
}

/// Runtime-loadable technology fingerprint for YAML packs.
#[derive(Debug, Clone, Deserialize)]
pub struct ExternalTechFingerprint {
    pub name: String,
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    #[serde(default)]
    pub banner_patterns: Vec<String>,
    #[serde(default)]
    pub body_patterns: Vec<String>,
    #[serde(default)]
    pub header_patterns: Vec<String>,
    pub version_pattern: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FingerprintPack {
    #[serde(default)]
    fingerprints: Vec<ExternalTechFingerprint>,
}

fn default_category() -> String {
    "technology".to_string()
}

fn default_confidence() -> f32 {
    0.70
}

/// Pre-compiled fingerprint with ready-to-use regexes.
struct CompiledFingerprint {
    name: &'static str,
    category: &'static str,
    confidence: f32,
    patterns: Vec<Regex>,
    version_regex: Option<Regex>,
    service: Option<&'static str>,
}

/// Get pre-compiled fingerprints (compiled once, reused for all banner matches).
fn compiled_fingerprints() -> &'static Vec<CompiledFingerprint> {
    static COMPILED: OnceLock<Vec<CompiledFingerprint>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        FINGERPRINTS
            .iter()
            .map(|fp| CompiledFingerprint {
                name: fp.name,
                category: fp.category,
                confidence: fp.confidence,
                patterns: fp
                    .banner_patterns
                    .iter()
                    .filter_map(|p| Regex::new(p).ok())
                    .collect(),
                version_regex: fp.version_pattern.and_then(|p| Regex::new(p).ok()),
                service: fp.service,
            })
            .collect()
    })
}

/// Get all built-in fingerprint definitions (for inspection/testing).
#[allow(dead_code)]
pub fn builtin_fingerprints() -> &'static [TechFingerprint] {
    FINGERPRINTS
}

static FINGERPRINTS: &[TechFingerprint] = &[
    // ═══════════════════════════════════════
    //  Web Servers
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "Apache",
        category: "web-server",
        confidence: 0.90,
        banner_patterns: &[r"(?i)Server:\s*Apache"],
        version_pattern: Some(r"(?i)Apache/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "Nginx",
        category: "web-server",
        confidence: 0.90,
        banner_patterns: &[r"(?i)Server:\s*nginx"],
        version_pattern: Some(r"(?i)nginx/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "Microsoft IIS",
        category: "web-server",
        confidence: 0.90,
        banner_patterns: &[r"(?i)Server:\s*Microsoft-IIS"],
        version_pattern: Some(r"(?i)Microsoft-IIS/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "LiteSpeed",
        category: "web-server",
        confidence: 0.90,
        banner_patterns: &[r"(?i)Server:\s*LiteSpeed"],
        version_pattern: Some(r"(?i)LiteSpeed/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "Caddy",
        category: "web-server",
        confidence: 0.85,
        banner_patterns: &[r"(?i)Server:\s*Caddy"],
        version_pattern: None,
        service: Some("http"),
    },
    TechFingerprint {
        name: "Tomcat",
        category: "web-server",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(Apache-Coyote|Tomcat)"],
        version_pattern: Some(r"(?i)Tomcat/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "Jetty",
        category: "web-server",
        confidence: 0.85,
        banner_patterns: &[r"(?i)Server:\s*Jetty"],
        version_pattern: Some(r"(?i)Jetty\(([\d.v]+)\)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "Lighttpd",
        category: "web-server",
        confidence: 0.90,
        banner_patterns: &[r"(?i)Server:\s*lighttpd"],
        version_pattern: Some(r"(?i)lighttpd/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "OpenResty",
        category: "web-server",
        confidence: 0.90,
        banner_patterns: &[r"(?i)Server:\s*openresty"],
        version_pattern: Some(r"(?i)openresty/([\d.]+)"),
        service: Some("http"),
    },
    // ═══════════════════════════════════════
    //  Frameworks & Languages
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "PHP",
        category: "framework",
        confidence: 0.90,
        banner_patterns: &[r"(?i)X-Powered-By:\s*PHP"],
        version_pattern: Some(r"(?i)PHP/([\d.]+)"),
        service: None,
    },
    TechFingerprint {
        name: "ASP.NET",
        category: "framework",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(X-AspNet-Version|X-Powered-By:\s*ASP\.NET)"],
        version_pattern: Some(r"(?i)X-AspNet-Version:\s*([\d.]+)"),
        service: None,
    },
    TechFingerprint {
        name: "Express",
        category: "framework",
        confidence: 0.85,
        banner_patterns: &[r"(?i)X-Powered-By:\s*Express"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Django",
        category: "framework",
        confidence: 0.70,
        banner_patterns: &[r"(?i)(csrfmiddlewaretoken|django)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Flask",
        category: "framework",
        confidence: 0.85,
        banner_patterns: &[r"(?i)Server:\s*Werkzeug"],
        version_pattern: Some(r"(?i)Werkzeug/([\d.]+)"),
        service: None,
    },
    TechFingerprint {
        name: "Rails",
        category: "framework",
        confidence: 0.75,
        banner_patterns: &[r"(?i)(X-Powered-By:\s*Phusion|X-Runtime|action_dispatch)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Spring",
        category: "framework",
        confidence: 0.75,
        banner_patterns: &[r"(?i)(X-Application-Context|Whitelabel Error Page)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Laravel",
        category: "framework",
        confidence: 0.70,
        banner_patterns: &[r"(?i)(laravel_session|XSRF-TOKEN)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Next.js",
        category: "framework",
        confidence: 0.75,
        banner_patterns: &[r"(?i)(x-nextjs|__next|_next/static)"],
        version_pattern: None,
        service: None,
    },
    // ═══════════════════════════════════════
    //  Databases
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "MySQL",
        category: "database",
        confidence: 0.90,
        banner_patterns: &[r"(?i)(mysql_native_password|MariaDB|mysql)"],
        version_pattern: Some(r"([\d.]+)-(MariaDB|MySQL|ubuntu|log)"),
        service: Some("mysql"),
    },
    TechFingerprint {
        name: "PostgreSQL",
        category: "database",
        confidence: 0.90,
        banner_patterns: &[r"(?i)PostgreSQL"],
        version_pattern: Some(r"(?i)PostgreSQL\s+([\d.]+)"),
        service: Some("postgresql"),
    },
    TechFingerprint {
        name: "MongoDB",
        category: "database",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(MongoDB|mongod|ismaster)"],
        version_pattern: None,
        service: Some("mongodb"),
    },
    TechFingerprint {
        name: "Redis",
        category: "database",
        confidence: 0.90,
        banner_patterns: &[r"(?i)(\-ERR|REDIS|redis_version)"],
        version_pattern: Some(r"redis_version:([\d.]+)"),
        service: Some("redis"),
    },
    TechFingerprint {
        name: "Memcached",
        category: "database",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(STAT|memcached)"],
        version_pattern: Some(r"(?i)VERSION\s+([\d.]+)"),
        service: Some("memcached"),
    },
    TechFingerprint {
        name: "Elasticsearch",
        category: "database",
        confidence: 0.90,
        banner_patterns: &[r#"(?i)(elasticsearch|"cluster_name"|"tagline"\s*:\s*"You Know)"#],
        version_pattern: Some(r#""number"\s*:\s*"([\d.]+)""#),
        service: Some("elasticsearch"),
    },
    TechFingerprint {
        name: "CouchDB",
        category: "database",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(couchdb|Welcome.*CouchDB)"],
        version_pattern: Some(r#""version"\s*:\s*"([\d.]+)""#),
        service: Some("couchdb"),
    },
    // ═══════════════════════════════════════
    //  Protocols — SSH
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "OpenSSH",
        category: "protocol",
        confidence: 0.95,
        banner_patterns: &[r"(?i)SSH-.*OpenSSH"],
        version_pattern: Some(r"OpenSSH_([\S]+)"),
        service: Some("ssh"),
    },
    TechFingerprint {
        name: "Dropbear SSH",
        category: "protocol",
        confidence: 0.90,
        banner_patterns: &[r"(?i)SSH-.*dropbear"],
        version_pattern: Some(r"dropbear_([\d.]+)"),
        service: Some("ssh"),
    },
    TechFingerprint {
        name: "SSH",
        category: "protocol",
        confidence: 0.60,
        banner_patterns: &[r"^SSH-[\d.]+-"],
        version_pattern: None,
        service: Some("ssh"),
    },
    // ═══════════════════════════════════════
    //  Protocols — FTP
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "vsftpd",
        category: "protocol",
        confidence: 0.90,
        banner_patterns: &[r"(?i)vsftpd"],
        version_pattern: Some(r"vsftpd\s+([\d.]+)"),
        service: Some("ftp"),
    },
    TechFingerprint {
        name: "ProFTPD",
        category: "protocol",
        confidence: 0.90,
        banner_patterns: &[r"(?i)ProFTPD"],
        version_pattern: Some(r"ProFTPD\s+([\d.]+)"),
        service: Some("ftp"),
    },
    TechFingerprint {
        name: "Pure-FTPd",
        category: "protocol",
        confidence: 0.85,
        banner_patterns: &[r"(?i)Pure-FTPd"],
        version_pattern: None,
        service: Some("ftp"),
    },
    TechFingerprint {
        name: "FTP",
        category: "protocol",
        confidence: 0.60,
        banner_patterns: &[r"^220[ -].*FTP"],
        version_pattern: None,
        service: Some("ftp"),
    },
    // ═══════════════════════════════════════
    //  Protocols — Mail
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "Postfix",
        category: "mail",
        confidence: 0.85,
        banner_patterns: &[r"(?i)Postfix"],
        version_pattern: None,
        service: Some("smtp"),
    },
    TechFingerprint {
        name: "Exim",
        category: "mail",
        confidence: 0.90,
        banner_patterns: &[r"(?i)Exim"],
        version_pattern: Some(r"(?i)Exim\s+([\d.]+)"),
        service: Some("smtp"),
    },
    TechFingerprint {
        name: "Dovecot",
        category: "mail",
        confidence: 0.85,
        banner_patterns: &[r"(?i)Dovecot"],
        version_pattern: None,
        service: Some("imap"),
    },
    TechFingerprint {
        name: "Exchange",
        category: "mail",
        confidence: 0.80,
        banner_patterns: &[r"(?i)(Microsoft ESMTP|Exchange)"],
        version_pattern: None,
        service: Some("smtp"),
    },
    TechFingerprint {
        name: "SMTP",
        category: "mail",
        confidence: 0.60,
        banner_patterns: &[r"^220[ -].*SMTP"],
        version_pattern: None,
        service: Some("smtp"),
    },
    // ═══════════════════════════════════════
    //  Proxies & Load Balancers
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "HAProxy",
        category: "proxy",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(Server:\s*HAProxy|X-HAProxy)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Varnish",
        category: "proxy",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(X-Varnish|Via:.*varnish)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Traefik",
        category: "proxy",
        confidence: 0.85,
        banner_patterns: &[r"(?i)Server:\s*Traefik"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Envoy",
        category: "proxy",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(Server:\s*envoy|x-envoy)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Squid",
        category: "proxy",
        confidence: 0.85,
        banner_patterns: &[r"(?i)Server:\s*squid"],
        version_pattern: Some(r"(?i)squid/([\d.]+)"),
        service: None,
    },
    // ═══════════════════════════════════════
    //  Cloud & CDN
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "Cloudflare",
        category: "cdn",
        confidence: 0.90,
        banner_patterns: &[r"(?i)(Server:\s*cloudflare|cf-ray|__cfduid)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "AWS (ELB/CloudFront)",
        category: "cloud",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(Server:\s*(awselb|AmazonS3|CloudFront)|x-amz-|x-amzn-)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Azure",
        category: "cloud",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(x-ms-|x-azure|Server:\s*Microsoft-Azure)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Google Cloud",
        category: "cloud",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(Server:\s*(gws|GSE|Google Frontend)|x-goog-)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Fastly",
        category: "cdn",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(x-fastly|fastly-|Server:\s*Fastly)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Akamai",
        category: "cdn",
        confidence: 0.85,
        banner_patterns: &[r"(?i)(X-Akamai|Server:\s*AkamaiGHost)"],
        version_pattern: None,
        service: None,
    },
    // ═══════════════════════════════════════
    //  CMS
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "WordPress",
        category: "cms",
        confidence: 0.75,
        banner_patterns: &[r"(?i)(wp-content|wp-includes|WordPress)"],
        version_pattern: Some(r#"(?i)WordPress\s+([\d.]+)"#),
        service: None,
    },
    TechFingerprint {
        name: "Joomla",
        category: "cms",
        confidence: 0.70,
        banner_patterns: &[r"(?i)(/administrator/|Joomla)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Drupal",
        category: "cms",
        confidence: 0.75,
        banner_patterns: &[r"(?i)(X-Generator:\s*Drupal|/sites/default/)"],
        version_pattern: Some(r"(?i)Drupal\s+([\d.]+)"),
        service: None,
    },
    // ═══════════════════════════════════════
    //  WAF Detection
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "ModSecurity WAF",
        category: "waf",
        confidence: 0.80,
        banner_patterns: &[r"(?i)(mod_security|NOYB|ModSecurity)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "AWS WAF",
        category: "waf",
        confidence: 0.80,
        banner_patterns: &[r"(?i)(x-amzn-waf|awswaf)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Imperva/Incapsula",
        category: "waf",
        confidence: 0.80,
        banner_patterns: &[r"(?i)(X-CDN:\s*Incapsula|incap_ses|visid_incap)"],
        version_pattern: None,
        service: None,
    },
    // ═══════════════════════════════════════
    //  DevOps, API, and Admin Surfaces
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "Kubernetes API",
        category: "orchestrator",
        confidence: 0.88,
        banner_patterns: &[r#"(?i)("kind"\s*:\s*"Status"|kubernetes|x-kubernetes)"#],
        version_pattern: Some(r#"(?i)gitVersion["']?\s*:\s*["']?v?([\w.\-]+)"#),
        service: Some("kubernetes"),
    },
    TechFingerprint {
        name: "Docker API",
        category: "container",
        confidence: 0.90,
        banner_patterns: &[r#"(?i)("ApiVersion"|"DockerVersion"|Docker-Experimental)"#],
        version_pattern: Some(r#""Version"\s*:\s*"([\w.\-]+)""#),
        service: Some("docker"),
    },
    TechFingerprint {
        name: "Prometheus",
        category: "monitoring",
        confidence: 0.86,
        banner_patterns: &[r"(?i)(Prometheus|/metrics|prometheus_engine_query_duration_seconds)"],
        version_pattern: None,
        service: Some("prometheus"),
    },
    TechFingerprint {
        name: "Grafana",
        category: "dashboard",
        confidence: 0.88,
        banner_patterns: &[r"(?i)(grafana_session|Grafana|/public/build/grafana)"],
        version_pattern: Some(r#"(?i)grafana(?:[/\s-]+)([\d.]+)"#),
        service: Some("grafana"),
    },
    TechFingerprint {
        name: "Kibana",
        category: "dashboard",
        confidence: 0.86,
        banner_patterns: &[r"(?i)(kbn-name|kbn-version|Kibana)"],
        version_pattern: Some(r"(?i)kbn-version:\s*([\d.]+)"),
        service: Some("kibana"),
    },
    TechFingerprint {
        name: "RabbitMQ Management",
        category: "message-queue",
        confidence: 0.86,
        banner_patterns: &[r"(?i)(RabbitMQ Management|basic realm=.RabbitMQ Management.|rabbitmq)"],
        version_pattern: None,
        service: Some("rabbitmq"),
    },
    TechFingerprint {
        name: "Jenkins",
        category: "ci-cd",
        confidence: 0.90,
        banner_patterns: &[r"(?i)(X-Jenkins|Jenkins-Crumb|Jenkins)"],
        version_pattern: Some(r"(?i)X-Jenkins:\s*([\d.]+)"),
        service: Some("jenkins"),
    },
    TechFingerprint {
        name: "GitLab",
        category: "scm",
        confidence: 0.86,
        banner_patterns: &[r"(?i)(_gitlab_session|GitLab|x-gitlab-)"],
        version_pattern: None,
        service: Some("gitlab"),
    },
    TechFingerprint {
        name: "Nexus Repository",
        category: "artifact-repository",
        confidence: 0.86,
        banner_patterns: &[r"(?i)(Nexus Repository Manager|NX-ANTI-CSRF-TOKEN|Sonatype Nexus)"],
        version_pattern: Some(r"(?i)Nexus Repository Manager\s*([\d.]+)"),
        service: Some("nexus"),
    },
    TechFingerprint {
        name: "SonarQube",
        category: "code-analysis",
        confidence: 0.86,
        banner_patterns: &[r"(?i)(SonarQube|X-SonarQube|sonarqube)"],
        version_pattern: None,
        service: Some("sonarqube"),
    },
    TechFingerprint {
        name: "MinIO",
        category: "object-storage",
        confidence: 0.88,
        banner_patterns: &[r"(?i)(MinIO|x-minio-|X-Amz-Request-Id)"],
        version_pattern: None,
        service: Some("minio"),
    },
    TechFingerprint {
        name: "HashiCorp Consul",
        category: "service-discovery",
        confidence: 0.86,
        banner_patterns: &[r"(?i)(X-Consul-|Consul UI|consul-index)"],
        version_pattern: None,
        service: Some("consul"),
    },
    TechFingerprint {
        name: "HashiCorp Vault",
        category: "secrets",
        confidence: 0.88,
        banner_patterns: &[r"(?i)(X-Vault-|Vault UI|vault-token)"],
        version_pattern: None,
        service: Some("vault"),
    },
    TechFingerprint {
        name: "Apache Kafka",
        category: "message-queue",
        confidence: 0.65,
        banner_patterns: &[r"(?i)(kafka|broker|metadata_request)"],
        version_pattern: None,
        service: Some("kafka"),
    },
    TechFingerprint {
        name: "MQTT",
        category: "iot-protocol",
        confidence: 0.72,
        banner_patterns: &[
            r"(?i)(MQTT|mosquitto|Connection Refused: unacceptable protocol version)",
        ],
        version_pattern: Some(r"(?i)mosquitto\s+([\d.]+)"),
        service: Some("mqtt"),
    },
    TechFingerprint {
        name: "SMB",
        category: "file-sharing",
        confidence: 0.68,
        banner_patterns: &[r"(?i)(smb|samba|NT LM 0\.12)"],
        version_pattern: Some(r"(?i)Samba\s+([\d.]+)"),
        service: Some("smb"),
    },
    TechFingerprint {
        name: "Admin Panel",
        category: "admin-panel",
        confidence: 0.62,
        banner_patterns: &[r"(?i)(admin panel|administrator login|dashboard login|control panel)"],
        version_pattern: None,
        service: None,
    },
    // ═══════════════════════════════════════
    //  Other Protocols
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "RDP",
        category: "protocol",
        confidence: 0.65,
        banner_patterns: &[r"\x03\x00"], // RDP protocol magic bytes
        version_pattern: None,
        service: Some("rdp"),
    },
    TechFingerprint {
        name: "VNC",
        category: "protocol",
        confidence: 0.90,
        banner_patterns: &[r"RFB \d{3}\.\d{3}"],
        version_pattern: Some(r"RFB (\d{3}\.\d{3})"),
        service: Some("vnc"),
    },
];

/// Load optional runtime technology fingerprint packs from YAML files.
///
/// Supported YAML shapes:
///   fingerprints:
///     - name: Example
///       category: framework
///       banner_patterns: ["(?i)example"]
///
/// or a single fingerprint document with name/banner_patterns at the top level.
pub fn load_fingerprint_packs(dir: &str) -> Vec<ExternalTechFingerprint> {
    if dir.trim().is_empty() {
        return Vec::new();
    }
    let mut files = Vec::new();
    if collect_yaml_files(Path::new(dir), &mut files).is_err() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for path in files {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for doc in content.split("\n---") {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }
            if let Ok(pack) = serde_yaml::from_str::<FingerprintPack>(doc) {
                out.extend(
                    pack.fingerprints
                        .into_iter()
                        .filter(valid_external_fingerprint),
                );
                continue;
            }
            if let Ok(fp) = serde_yaml::from_str::<ExternalTechFingerprint>(doc) {
                if valid_external_fingerprint(&fp) {
                    out.push(fp);
                }
            }
        }
    }
    out
}

fn valid_external_fingerprint(fp: &ExternalTechFingerprint) -> bool {
    !fp.name.trim().is_empty()
        && (!fp.banner_patterns.is_empty()
            || !fp.body_patterns.is_empty()
            || !fp.header_patterns.is_empty())
}

fn collect_yaml_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let _ = collect_yaml_files(&path, out);
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml") {
            out.push(path);
        }
    }
    Ok(())
}

/// Match all built-in fingerprints against a raw banner/response string.
/// Returns: (tech_matches, service_name, version_string)
///
/// Uses pre-compiled regexes (compiled once on first call via OnceLock).
pub fn detect_technologies(raw: &str) -> (Vec<TechMatch>, Option<String>, Option<String>) {
    let mut matches = Vec::new();
    let mut service: Option<String> = None;
    let mut version: Option<String> = None;

    for fp in compiled_fingerprints() {
        let mut matched_evidence = None;

        for pattern in &fp.patterns {
            if let Some(m) = pattern.find(raw) {
                matched_evidence = Some(m.as_str().to_string());
                break;
            }
        }

        if let Some(evidence) = matched_evidence {
            // Extract version if available
            let ver = fp.version_regex.as_ref().and_then(|re| {
                re.captures(raw)
                    .and_then(|caps| caps.get(1))
                    .map(|m| format!("{} {}", fp.name, m.as_str()))
            });

            matches.push(TechMatch {
                name: fp.name.to_string(),
                category: fp.category.to_string(),
                confidence: fp.confidence,
                version: ver.clone(),
                evidence,
                source: "builtin".to_string(),
            });

            // First service match wins
            if service.is_none() {
                if let Some(svc) = fp.service {
                    service = Some(svc.to_string());
                }
            }

            // First version match wins
            if version.is_none() {
                if let Some(ref v) = ver {
                    version = Some(v.clone());
                }
            }
        }
    }

    (matches, service, version)
}

/// Match built-in and runtime-loaded fingerprints against a raw response.
pub fn detect_technologies_with_custom(
    raw: &str,
    custom: &[ExternalTechFingerprint],
) -> (Vec<TechMatch>, Option<String>, Option<String>) {
    let (mut matches, mut service, mut version) = detect_technologies(raw);

    for fp in custom {
        let patterns = fp
            .banner_patterns
            .iter()
            .chain(fp.header_patterns.iter())
            .chain(fp.body_patterns.iter());

        let mut matched_evidence = None;
        for pattern in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(m) = re.find(raw) {
                    matched_evidence = Some(m.as_str().to_string());
                    break;
                }
            }
        }

        if let Some(evidence) = matched_evidence {
            let ver = fp.version_pattern.as_ref().and_then(|pattern| {
                Regex::new(pattern)
                    .ok()
                    .and_then(|re| re.captures(raw))
                    .and_then(|caps| caps.get(1).map(|m| format!("{} {}", fp.name, m.as_str())))
            });

            if !matches
                .iter()
                .any(|m| m.name.eq_ignore_ascii_case(&fp.name))
            {
                matches.push(TechMatch {
                    name: fp.name.clone(),
                    category: fp.category.clone(),
                    confidence: fp.confidence,
                    version: ver.clone(),
                    evidence,
                    source: "yaml-fingerprint".to_string(),
                });
            }

            if service.is_none() {
                service = fp.service.clone();
            }
            if version.is_none() {
                version = ver;
            }
        }
    }

    matches.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });

    (matches, service, version)
}

/// Detect service by well-known port number (fallback when no banner match).
pub fn service_by_port(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 | 465 | 587 => Some("smtp"),
        53 => Some("dns"),
        80 | 8080 | 8000 | 8888 | 3000 | 5000 => Some("http"),
        110 => Some("pop3"),
        111 => Some("rpc"),
        135 => Some("msrpc"),
        139 => Some("netbios"),
        143 | 993 => Some("imap"),
        443 | 8443 | 9443 => Some("https"),
        445 => Some("smb"),
        1883 | 8883 => Some("mqtt"),
        995 => Some("pop3s"),
        2375 | 2376 => Some("docker"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        5672 | 15672 => Some("rabbitmq"),
        1723 => Some("pptp"),
        2049 => Some("nfs"),
        2181 => Some("zookeeper"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5900 | 5901 => Some("vnc"),
        6379 => Some("redis"),
        6667 => Some("irc"),
        8200 => Some("vault"),
        8500 => Some("consul"),
        9200 => Some("elasticsearch"),
        9092 => Some("kafka"),
        9090 => Some("prometheus"),
        11211 => Some("memcached"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_nginx() {
        let (matches, svc, ver) =
            detect_technologies("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n");
        assert!(matches.iter().any(|m| m.name == "Nginx"));
        assert_eq!(svc, Some("http".to_string()));
        assert_eq!(ver, Some("Nginx 1.24.0".to_string()));
        // Verify confidence and category propagation
        let nginx = matches.iter().find(|m| m.name == "Nginx").unwrap();
        assert_eq!(nginx.category, "web-server");
        assert!(nginx.confidence >= 0.85);
        assert_eq!(nginx.source, "builtin");
    }

    #[test]
    fn test_detect_openssh() {
        let (matches, svc, ver) = detect_technologies("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1");
        assert!(matches.iter().any(|m| m.name == "OpenSSH"));
        assert_eq!(svc, Some("ssh".to_string()));
        assert!(ver.unwrap().contains("8.9p1"));
    }

    #[test]
    fn test_detect_cloudflare() {
        let (matches, _, _) = detect_technologies("Server: cloudflare\r\ncf-ray: abc123\r\n");
        assert!(matches.iter().any(|m| m.name == "Cloudflare"));
    }

    #[test]
    fn test_detect_wordpress() {
        let (matches, _, _) =
            detect_technologies("<link rel='stylesheet' href='/wp-content/themes/test/style.css'>");
        assert!(matches.iter().any(|m| m.name == "WordPress"));
        let wp = matches.iter().find(|m| m.name == "WordPress").unwrap();
        assert_eq!(wp.category, "cms");
    }

    #[test]
    fn test_service_by_port() {
        assert_eq!(service_by_port(22), Some("ssh"));
        assert_eq!(service_by_port(80), Some("http"));
        assert_eq!(service_by_port(3306), Some("mysql"));
        assert_eq!(service_by_port(9090), Some("prometheus"));
        assert_eq!(service_by_port(15672), Some("rabbitmq"));
        assert_eq!(service_by_port(2375), Some("docker"));
        assert_eq!(service_by_port(12345), None);
    }

    #[test]
    fn test_confidence_ordering() {
        // OpenSSH (specific) should have higher confidence than generic SSH
        let (matches, _, _) = detect_technologies("SSH-2.0-OpenSSH_8.9p1");
        let openssh = matches.iter().find(|m| m.name == "OpenSSH").unwrap();
        let generic = matches.iter().find(|m| m.name == "SSH");
        assert!(openssh.confidence > generic.map(|g| g.confidence).unwrap_or(0.0));
    }

    #[test]
    fn test_detect_devops_surfaces() {
        let (matches, svc, _) = detect_technologies("HTTP/1.1 200 OK\r\nX-Jenkins: 2.440\r\n");
        assert!(matches.iter().any(|m| m.name == "Jenkins"));
        assert_eq!(svc, Some("jenkins".to_string()));

        let (matches, svc, _) =
            detect_technologies("{\"ApiVersion\":\"1.45\",\"DockerVersion\":\"26.1.0\"}");
        assert!(matches.iter().any(|m| m.name == "Docker API"));
        assert_eq!(svc, Some("docker".to_string()));
    }

    #[test]
    fn test_load_yaml_fingerprint_pack_and_detect() {
        let dir = std::env::temp_dir().join(format!(
            "akemi-fp-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fingerprints.yml");
        std::fs::write(
            &path,
            r#"
fingerprints:
  - name: Akemi Test Stack
    category: framework
    confidence: 0.93
    banner_patterns:
      - "(?i)x-akemi-test"
    version_pattern: "AkemiTest/([0-9.]+)"
    service: akemi-test
"#,
        )
        .unwrap();

        let custom = load_fingerprint_packs(dir.to_str().unwrap());
        let (matches, svc, version) = detect_technologies_with_custom(
            "HTTP/1.1 200 OK\r\nX-Akemi-Test: AkemiTest/1.2.3\r\n",
            &custom,
        );

        assert!(matches.iter().any(|m| {
            m.name == "Akemi Test Stack" && m.source == "yaml-fingerprint" && m.confidence > 0.9
        }));
        assert_eq!(svc, Some("akemi-test".to_string()));
        assert_eq!(version, Some("Akemi Test Stack 1.2.3".to_string()));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(dir);
    }
}
