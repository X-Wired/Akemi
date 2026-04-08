// tech_detect.rs — Built-in technology fingerprint database
//
// 50+ signatures compiled into the binary for zero-config tech detection.
// Covers: web servers, frameworks, databases, proxies, CDN/cloud, CMS, WAFs,
// protocols (SSH, FTP, SMTP, DNS), and more.
//
// These supplement YAML probe templates — user templates take priority.

use regex::Regex;

/// A single technology fingerprint.
pub struct TechFingerprint {
    pub name: &'static str,
    pub category: &'static str,
    /// Patterns to match against raw banner/response text.
    pub banner_patterns: &'static [&'static str],
    /// If set, also extract the version via this capture group pattern.
    pub version_pattern: Option<&'static str>,
    /// Service name to assign (e.g. "http", "ssh", "mysql")
    pub service: Option<&'static str>,
}

/// Get all built-in fingerprints.
pub fn builtin_fingerprints() -> &'static [TechFingerprint] {
    &FINGERPRINTS
}

static FINGERPRINTS: [TechFingerprint; 56] = [
    // ═══════════════════════════════════════
    //  Web Servers
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "Apache",
        category: "web-server",
        banner_patterns: &[r"(?i)Server:\s*Apache"],
        version_pattern: Some(r"(?i)Apache/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "Nginx",
        category: "web-server",
        banner_patterns: &[r"(?i)Server:\s*nginx"],
        version_pattern: Some(r"(?i)nginx/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "Microsoft IIS",
        category: "web-server",
        banner_patterns: &[r"(?i)Server:\s*Microsoft-IIS"],
        version_pattern: Some(r"(?i)Microsoft-IIS/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "LiteSpeed",
        category: "web-server",
        banner_patterns: &[r"(?i)Server:\s*LiteSpeed"],
        version_pattern: Some(r"(?i)LiteSpeed/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "Caddy",
        category: "web-server",
        banner_patterns: &[r"(?i)Server:\s*Caddy"],
        version_pattern: None,
        service: Some("http"),
    },
    TechFingerprint {
        name: "Tomcat",
        category: "web-server",
        banner_patterns: &[r"(?i)(Apache-Coyote|Tomcat)"],
        version_pattern: Some(r"(?i)Tomcat/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "Jetty",
        category: "web-server",
        banner_patterns: &[r"(?i)Server:\s*Jetty"],
        version_pattern: Some(r"(?i)Jetty\(([\d.v]+)\)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "Lighttpd",
        category: "web-server",
        banner_patterns: &[r"(?i)Server:\s*lighttpd"],
        version_pattern: Some(r"(?i)lighttpd/([\d.]+)"),
        service: Some("http"),
    },
    TechFingerprint {
        name: "OpenResty",
        category: "web-server",
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
        banner_patterns: &[r"(?i)X-Powered-By:\s*PHP"],
        version_pattern: Some(r"(?i)PHP/([\d.]+)"),
        service: None,
    },
    TechFingerprint {
        name: "ASP.NET",
        category: "framework",
        banner_patterns: &[r"(?i)(X-AspNet-Version|X-Powered-By:\s*ASP\.NET)"],
        version_pattern: Some(r"(?i)X-AspNet-Version:\s*([\d.]+)"),
        service: None,
    },
    TechFingerprint {
        name: "Express",
        category: "framework",
        banner_patterns: &[r"(?i)X-Powered-By:\s*Express"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Django",
        category: "framework",
        banner_patterns: &[r"(?i)(csrfmiddlewaretoken|django)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Flask",
        category: "framework",
        banner_patterns: &[r"(?i)Server:\s*Werkzeug"],
        version_pattern: Some(r"(?i)Werkzeug/([\d.]+)"),
        service: None,
    },
    TechFingerprint {
        name: "Rails",
        category: "framework",
        banner_patterns: &[r"(?i)(X-Powered-By:\s*Phusion|X-Runtime|action_dispatch)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Spring",
        category: "framework",
        banner_patterns: &[r"(?i)(X-Application-Context|Whitelabel Error Page)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Laravel",
        category: "framework",
        banner_patterns: &[r"(?i)(laravel_session|XSRF-TOKEN)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Next.js",
        category: "framework",
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
        banner_patterns: &[r"(?i)(mysql_native_password|MariaDB|mysql)"],
        version_pattern: Some(r"([\d.]+)-(MariaDB|MySQL|ubuntu|log)"),
        service: Some("mysql"),
    },
    TechFingerprint {
        name: "PostgreSQL",
        category: "database",
        banner_patterns: &[r"(?i)PostgreSQL"],
        version_pattern: Some(r"(?i)PostgreSQL\s+([\d.]+)"),
        service: Some("postgresql"),
    },
    TechFingerprint {
        name: "MongoDB",
        category: "database",
        banner_patterns: &[r"(?i)(MongoDB|mongod|ismaster)"],
        version_pattern: None,
        service: Some("mongodb"),
    },
    TechFingerprint {
        name: "Redis",
        category: "database",
        banner_patterns: &[r"(?i)(\-ERR|REDIS|redis_version)"],
        version_pattern: Some(r"redis_version:([\d.]+)"),
        service: Some("redis"),
    },
    TechFingerprint {
        name: "Memcached",
        category: "database",
        banner_patterns: &[r"(?i)(STAT|memcached)"],
        version_pattern: Some(r"(?i)VERSION\s+([\d.]+)"),
        service: Some("memcached"),
    },
    TechFingerprint {
        name: "Elasticsearch",
        category: "database",
        banner_patterns: &[r#"(?i)(elasticsearch|"cluster_name"|"tagline"\s*:\s*"You Know)"#],
        version_pattern: Some(r#""number"\s*:\s*"([\d.]+)""#),
        service: Some("elasticsearch"),
    },
    TechFingerprint {
        name: "CouchDB",
        category: "database",
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
        banner_patterns: &[r"(?i)SSH-.*OpenSSH"],
        version_pattern: Some(r"OpenSSH_([\S]+)"),
        service: Some("ssh"),
    },
    TechFingerprint {
        name: "Dropbear SSH",
        category: "protocol",
        banner_patterns: &[r"(?i)SSH-.*dropbear"],
        version_pattern: Some(r"dropbear_([\d.]+)"),
        service: Some("ssh"),
    },
    TechFingerprint {
        name: "SSH",
        category: "protocol",
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
        banner_patterns: &[r"(?i)vsftpd"],
        version_pattern: Some(r"vsftpd\s+([\d.]+)"),
        service: Some("ftp"),
    },
    TechFingerprint {
        name: "ProFTPD",
        category: "protocol",
        banner_patterns: &[r"(?i)ProFTPD"],
        version_pattern: Some(r"ProFTPD\s+([\d.]+)"),
        service: Some("ftp"),
    },
    TechFingerprint {
        name: "Pure-FTPd",
        category: "protocol",
        banner_patterns: &[r"(?i)Pure-FTPd"],
        version_pattern: None,
        service: Some("ftp"),
    },
    TechFingerprint {
        name: "FTP",
        category: "protocol",
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
        banner_patterns: &[r"(?i)Postfix"],
        version_pattern: None,
        service: Some("smtp"),
    },
    TechFingerprint {
        name: "Exim",
        category: "mail",
        banner_patterns: &[r"(?i)Exim"],
        version_pattern: Some(r"(?i)Exim\s+([\d.]+)"),
        service: Some("smtp"),
    },
    TechFingerprint {
        name: "Dovecot",
        category: "mail",
        banner_patterns: &[r"(?i)Dovecot"],
        version_pattern: None,
        service: Some("imap"),
    },
    TechFingerprint {
        name: "Exchange",
        category: "mail",
        banner_patterns: &[r"(?i)(Microsoft ESMTP|Exchange)"],
        version_pattern: None,
        service: Some("smtp"),
    },
    TechFingerprint {
        name: "SMTP",
        category: "mail",
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
        banner_patterns: &[r"(?i)(Server:\s*HAProxy|X-HAProxy)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Varnish",
        category: "proxy",
        banner_patterns: &[r"(?i)(X-Varnish|Via:.*varnish)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Traefik",
        category: "proxy",
        banner_patterns: &[r"(?i)Server:\s*Traefik"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Envoy",
        category: "proxy",
        banner_patterns: &[r"(?i)(Server:\s*envoy|x-envoy)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Squid",
        category: "proxy",
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
        banner_patterns: &[r"(?i)(Server:\s*cloudflare|cf-ray|__cfduid)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "AWS (ELB/CloudFront)",
        category: "cloud",
        banner_patterns: &[r"(?i)(Server:\s*(awselb|AmazonS3|CloudFront)|x-amz-|x-amzn-)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Azure",
        category: "cloud",
        banner_patterns: &[r"(?i)(x-ms-|x-azure|Server:\s*Microsoft-Azure)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Google Cloud",
        category: "cloud",
        banner_patterns: &[r"(?i)(Server:\s*(gws|GSE|Google Frontend)|x-goog-)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Fastly",
        category: "cdn",
        banner_patterns: &[r"(?i)(x-fastly|fastly-|Server:\s*Fastly)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Akamai",
        category: "cdn",
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
        banner_patterns: &[r"(?i)(wp-content|wp-includes|WordPress)"],
        version_pattern: Some(r#"(?i)WordPress\s+([\d.]+)"#),
        service: None,
    },
    TechFingerprint {
        name: "Joomla",
        category: "cms",
        banner_patterns: &[r"(?i)(/administrator/|Joomla)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Drupal",
        category: "cms",
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
        banner_patterns: &[r"(?i)(mod_security|NOYB|ModSecurity)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "AWS WAF",
        category: "waf",
        banner_patterns: &[r"(?i)(x-amzn-waf|awswaf)"],
        version_pattern: None,
        service: None,
    },
    TechFingerprint {
        name: "Imperva/Incapsula",
        category: "waf",
        banner_patterns: &[r"(?i)(X-CDN:\s*Incapsula|incap_ses|visid_incap)"],
        version_pattern: None,
        service: None,
    },

    // ═══════════════════════════════════════
    //  Other Protocols
    // ═══════════════════════════════════════
    TechFingerprint {
        name: "RDP",
        category: "protocol",
        banner_patterns: &[r"\x03\x00"],  // RDP protocol magic bytes
        version_pattern: None,
        service: Some("rdp"),
    },
    TechFingerprint {
        name: "VNC",
        category: "protocol",
        banner_patterns: &[r"RFB \d{3}\.\d{3}"],
        version_pattern: Some(r"RFB (\d{3}\.\d{3})"),
        service: Some("vnc"),
    },
];

/// Match all built-in fingerprints against a raw banner/response string.
/// Returns: (matched_technologies, service_name, version_string)
pub fn detect_technologies(raw: &str) -> (Vec<String>, Option<String>, Option<String>) {
    let mut technologies = Vec::new();
    let mut service: Option<String> = None;
    let mut version: Option<String> = None;

    for fp in builtin_fingerprints() {
        let mut matched = false;

        for pattern_str in fp.banner_patterns {
            if let Ok(re) = Regex::new(pattern_str) {
                if re.is_match(raw) {
                    matched = true;
                    break;
                }
            }
        }

        if matched {
            if !technologies.contains(&fp.name.to_string()) {
                technologies.push(fp.name.to_string());
            }

            // Extract service name (first match wins)
            if service.is_none() {
                if let Some(svc) = fp.service {
                    service = Some(svc.to_string());
                }
            }

            // Try extracting version
            if version.is_none() {
                if let Some(ver_pattern) = fp.version_pattern {
                    if let Ok(re) = Regex::new(ver_pattern) {
                        if let Some(caps) = re.captures(raw) {
                            if let Some(ver_match) = caps.get(1) {
                                version = Some(format!("{} {}", fp.name, ver_match.as_str()));
                            }
                        }
                    }
                }
            }
        }
    }

    (technologies, service, version)
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
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        1723 => Some("pptp"),
        2049 => Some("nfs"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5900 | 5901 => Some("vnc"),
        6379 => Some("redis"),
        6667 => Some("irc"),
        9090 => Some("http-proxy"),
        9200 => Some("elasticsearch"),
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
        let (techs, svc, ver) = detect_technologies("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n");
        assert!(techs.contains(&"Nginx".to_string()));
        assert_eq!(svc, Some("http".to_string()));
        assert_eq!(ver, Some("Nginx 1.24.0".to_string()));
    }

    #[test]
    fn test_detect_openssh() {
        let (techs, svc, ver) = detect_technologies("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1");
        assert!(techs.contains(&"OpenSSH".to_string()));
        assert_eq!(svc, Some("ssh".to_string()));
        assert!(ver.unwrap().contains("8.9p1"));
    }

    #[test]
    fn test_detect_cloudflare() {
        let (techs, _, _) = detect_technologies("Server: cloudflare\r\ncf-ray: abc123\r\n");
        assert!(techs.contains(&"Cloudflare".to_string()));
    }

    #[test]
    fn test_detect_wordpress() {
        let (techs, _, _) = detect_technologies("<link rel='stylesheet' href='/wp-content/themes/test/style.css'>");
        assert!(techs.contains(&"WordPress".to_string()));
    }

    #[test]
    fn test_service_by_port() {
        assert_eq!(service_by_port(22), Some("ssh"));
        assert_eq!(service_by_port(80), Some("http"));
        assert_eq!(service_by_port(3306), Some("mysql"));
        assert_eq!(service_by_port(12345), None);
    }
}
