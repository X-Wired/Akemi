// main.rs — Entry point for Akemi-Spear
//
// Three modes:
//   1. Stdin mode (default): reads ScanRequest JSON from stdin, writes ScanResult to stdout
//   2. CLI mode: accepts flags directly for standalone use
//   3. Discovery mode (--no-port): CIDR host alive sweep
//
// Progress and logs go to stderr so they don't pollute the JSON output.

mod banner_grabber;
mod host_discovery;
mod models;
mod rate_limiter;
mod resume;
mod scanner;
mod syn_scanner;
mod tech_detect;

use clap::Parser;
use models::ScanRequest;
use std::io::{self, Read};

/// Akemi Scanner — High-performance port scanning & network reconnaissance engine
#[derive(Parser, Debug)]
#[command(name = "Akemi-Spear")]
#[command(about = "High-performance port scanner and network reconnaissance engine for Akemi")]
#[command(version = "0.2.0")]
struct Cli {
    /// Target host, IP, or CIDR range (e.g. "192.168.1.0/24")
    #[arg(long)]
    host: Option<String>,

    /// Comma-separated ports or ranges (e.g. "22,80,443,1-1024")
    #[arg(short, long, default_value = "")]
    ports: String,

    /// Maximum concurrent connections
    #[arg(short = 'c', long, default_value = "200")]
    threads: u32,

    /// Timeout per port in milliseconds
    #[arg(short = 'T', long, default_value = "3000")]
    timeout_ms: u64,

    /// Rate limit: connections per second (0 = unlimited)
    #[arg(long, default_value = "0")]
    rate: f64,

    /// Retries for timed-out ports
    #[arg(long, default_value = "1")]
    retries: u32,

    /// Randomize port scan order
    #[arg(long, default_value = "true")]
    randomize: bool,

    /// Use SYN scan mode (requires admin/root privileges)
    #[arg(long)]
    syn: bool,

    /// Perform banner grabbing on open ports
    #[arg(long, default_value = "true")]
    banner_grab: bool,

    /// Directory containing YAML probe templates
    #[arg(long, default_value = "")]
    probe_dir: String,

    /// Path to scan state file for resume
    #[arg(long, default_value = "")]
    resume_file: String,

    /// Read ScanRequest JSON from stdin instead of CLI args
    #[arg(long)]
    stdin: bool,

    /// Verbose output (show progress, headers)
    #[arg(short, long)]
    verbose: bool,

    /// Host discovery only — no port scanning (for CIDR sweeps)
    #[arg(long = "no-port")]
    no_port: bool,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();

    // Check if this is a host discovery request (CIDR or --no-port)
    if cli.no_port
        || cli
            .host
            .as_ref()
            .map_or(false, |h| host_discovery::is_cidr(h))
    {
        run_discovery_mode(&cli).await;
        return;
    }

    let request = if cli.stdin || cli.host.is_none() {
        // Stdin mode: read JSON from stdin
        let req = read_request_from_stdin();
        match req {
            Ok(r) if r.no_port => {
                // Discovery mode via stdin
                run_discovery_from_request(&r).await;
                return;
            }
            other => other,
        }
    } else {
        // CLI mode: build request from flags
        build_request_from_cli(&cli)
    };

    let request = match request {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[!] Error: {}", e);
            std::process::exit(1);
        }
    };

    if request.ports.is_empty() {
        eprintln!("[!] No ports specified");
        std::process::exit(1);
    }

    if request.verbose {
        // Print header to stderr
        eprintln!();
        eprintln!("    ╔══════════════════════════════════════╗");
        eprintln!(
            "    ║   Akemi-Spear v{}  (Rust)         ║",
            env!("CARGO_PKG_VERSION")
        );
        eprintln!("    ║   Network Reconnaissance Engine       ║");
        eprintln!("    ╚══════════════════════════════════════╝");
        eprintln!();
    }

    // Run the scan
    let result = if request.syn_mode {
        syn_scanner::inner::run_syn_scan(&request).await
    } else {
        scanner::run_connect_scan(&request).await
    };

    match result {
        Ok(scan_result) => match serde_json::to_string_pretty(&scan_result) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("[!] Error serializing result: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("[!] Scan error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Run host discovery from CLI flags.
async fn run_discovery_mode(cli: &Cli) {
    let host = match &cli.host {
        Some(h) => h.clone(),
        None => {
            eprintln!("[!] --host is required for discovery mode");
            std::process::exit(1);
        }
    };

    if cli.verbose {
        eprintln!();
        eprintln!("    ╔══════════════════════════════════════╗");
        eprintln!(
            "    ║   Akemi-Spear v{}  (Rust)         ║",
            env!("CARGO_PKG_VERSION")
        );
        eprintln!("    ║   Host Discovery Mode                 ║");
        eprintln!("    ╚══════════════════════════════════════╝");
        eprintln!();
    }

    let ips = if host_discovery::is_cidr(&host) {
        match host_discovery::parse_cidr(&host) {
            Ok(ips) => ips,
            Err(e) => {
                eprintln!("[!] CIDR parse error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Single host — resolve and check
        match host.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => vec![ip],
            Err(_) => {
                eprintln!(
                    "[!] For discovery mode, provide an IP or CIDR range (e.g. 192.168.1.0/24)"
                );
                std::process::exit(1);
            }
        }
    };

    let result = host_discovery::run_host_discovery(
        &ips,
        cli.threads,
        cli.timeout_ms,
        cli.rate,
        cli.verbose,
    )
    .await;

    match serde_json::to_string_pretty(&result) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("[!] Error serializing result: {}", e);
            std::process::exit(1);
        }
    }
}

/// Run host discovery from a ScanRequest received via stdin.
async fn run_discovery_from_request(req: &ScanRequest) {
    let ips = if host_discovery::is_cidr(&req.host) {
        match host_discovery::parse_cidr(&req.host) {
            Ok(ips) => ips,
            Err(e) => {
                eprintln!("[!] CIDR parse error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match req.host.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => vec![ip],
            Err(_) => {
                eprintln!("[!] For discovery mode, provide an IP or CIDR range");
                std::process::exit(1);
            }
        }
    };

    let result = host_discovery::run_host_discovery(
        &ips,
        req.threads,
        req.timeout_ms,
        req.rate,
        req.verbose,
    )
    .await;

    match serde_json::to_string_pretty(&result) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("[!] Error serializing result: {}", e);
            std::process::exit(1);
        }
    }
}

/// Read a ScanRequest JSON from stdin.
fn read_request_from_stdin() -> Result<ScanRequest, String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("Error reading stdin: {}", e))?;

    serde_json::from_str(&input).map_err(|e| format!("Error parsing JSON from stdin: {}", e))
}

/// Build a ScanRequest from CLI arguments.
fn build_request_from_cli(cli: &Cli) -> Result<ScanRequest, String> {
    let host = cli.host.as_ref().ok_or("--host is required")?.clone();
    let ports = parse_ports(&cli.ports)?;

    Ok(ScanRequest {
        host,
        ports,
        threads: cli.threads,
        timeout_ms: cli.timeout_ms,
        rate: cli.rate,
        retries: cli.retries,
        randomize: cli.randomize,
        syn_mode: cli.syn,
        banner_grab: cli.banner_grab,
        probe_templates_dir: cli.probe_dir.clone(),
        resume_file: cli.resume_file.clone(),
        verbose: cli.verbose,
        no_port: cli.no_port,
    })
}

/// Parse a port specification string like "22,80,443,1-1024" into a sorted, deduplicated vec.
fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = std::collections::HashSet::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start_s, end_s)) = part.split_once('-') {
            let start: u16 = start_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range start: {}", start_s))?;
            let end: u16 = end_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range end: {}", end_s))?;
            if start > end {
                return Err(format!("Invalid port range: {}-{}", start, end));
            }
            for p in start..=end {
                ports.insert(p);
            }
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| format!("Invalid port: {}", part))?;
            ports.insert(port);
        }
    }

    let mut result: Vec<u16> = ports.into_iter().collect();
    result.sort();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_ports() {
        let result = parse_ports("22,80,443").unwrap();
        assert_eq!(result, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_port_range() {
        let result = parse_ports("1-5").unwrap();
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_mixed() {
        let result = parse_ports("22,80,100-102,443").unwrap();
        assert_eq!(result, vec![22, 80, 100, 101, 102, 443]);
    }

    #[test]
    fn test_parse_deduplicate() {
        let result = parse_ports("22,22,80,80").unwrap();
        assert_eq!(result, vec![22, 80]);
    }

    #[test]
    fn test_parse_empty() {
        let result = parse_ports("").unwrap();
        assert_eq!(result, Vec::<u16>::new());
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_ports("abc").is_err());
    }
}
