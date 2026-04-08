// scanner.rs — Core connect-scan engine with rate limiting, randomization, and retry
use crate::banner_grabber::{grab_banner, load_tcp_templates};
use crate::models::{PortResult, ProbeTemplate, ScanRequest, ScanResult, ScanState};
use crate::rate_limiter::RateLimiter;
use crate::resume::{filter_remaining_ports, load_state, save_state};
use log::{debug, info};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Run a full connect-based port scan.
///
/// Architecture: connect-checks are gated by a semaphore (concurrency = threads).
/// Banner grabbing runs in a *separate* unbounded task pool so that enriching an
/// open port never blocks other connection attempts.
pub async fn run_connect_scan(req: &ScanRequest) -> Result<ScanResult, String> {
    let start = Instant::now();

    // Resolve host → IPs
    let ips = resolve_host(&req.host)?;
    let target_ip = ips[0].clone();

    info!("[*] Connect scan on {} ({}) — {} ports, {} threads",
        req.host, target_ip, req.ports.len(), req.threads);

    // DNS enrichment: reverse DNS for all resolved IPs
    let mut rdns_map: HashMap<String, String> = HashMap::new();
    for ip in &ips {
        if let Some(hostname) = reverse_dns_lookup(ip) {
            rdns_map.insert(ip.clone(), hostname);
        }
    }

    // Display IP enrichment
    eprintln!("[*] Target: {}", req.host);
    for ip in &ips {
        if let Some(rdns) = rdns_map.get(ip) {
            eprintln!("    \x1b[36m→\x1b[0m {} (\x1b[90m{}\x1b[0m)", ip, rdns);
        } else {
            eprintln!("    \x1b[36m→\x1b[0m {}", ip);
        }
    }

    // Load probe templates for banner grabbing
    let tcp_templates: Arc<Vec<ProbeTemplate>> = Arc::new(if req.banner_grab {
        load_tcp_templates(&req.probe_templates_dir)
    } else {
        Vec::new()
    });

    // Load resume state
    let state = load_state(&req.resume_file);
    let mut ports = filter_remaining_ports(&req.ports, &state);

    // Randomize port order
    if req.randomize {
        let mut rng = rand::rng();
        ports.shuffle(&mut rng);
    }

    let total_ports = ports.len() as u32;

    // Rate limiter
    let rate_limiter = RateLimiter::new(req.rate, req.threads);

    // Shared state
    let open_ports: Arc<Mutex<Vec<PortResult>>> = Arc::new(Mutex::new(Vec::new()));
    let scanned_count = Arc::new(AtomicU32::new(0));
    let open_count = Arc::new(AtomicU32::new(0));
    let scanned_list = Arc::new(Mutex::new(
        state.as_ref().map_or(Vec::new(), |s| s.scanned_ports.clone())
    ));

    // Semaphore for concurrency control — gates connect attempts only
    let sem = Arc::new(tokio::sync::Semaphore::new(req.threads as usize));

    // Separate tracker for in-flight banner grabs so we can await them at the end
    let banner_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> =
        Arc::new(Mutex::new(Vec::new()));

    // Progress reporting task
    let scanned_for_progress = scanned_count.clone();
    let open_for_progress = open_count.clone();
    let verbose = req.verbose;
    let progress_handle = tokio::spawn(async move {
        let progress_start = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let current = scanned_for_progress.load(Ordering::Relaxed);
            let open = open_for_progress.load(Ordering::Relaxed);
            let elapsed_secs = progress_start.elapsed().as_secs_f64().max(0.1);
            let rate = current as f64 / elapsed_secs;
            if verbose {
                eprintln!("[progress] {}/{} scanned | {} open | {:.0} ports/sec",
                    current, total_ports, open, rate);
            }
            if current >= total_ports {
                break;
            }
        }
    });

    // Spawn ALL scan tasks up front — the semaphore gates concurrency internally
    let mut handles = Vec::new();

    for port in ports {
        let sem = sem.clone();
        let rl = rate_limiter.clone();
        let ip = target_ip.clone();
        let timeout_ms = req.timeout_ms;
        let retries = req.retries;
        let banner_grab = req.banner_grab;
        let templates = tcp_templates.clone();
        let open_ports = open_ports.clone();
        let scanned_count = scanned_count.clone();
        let open_count = open_count.clone();
        let scanned_list = scanned_list.clone();
        let resume_file = req.resume_file.clone();
        let host = req.host.clone();
        let banner_handles = banner_handles.clone();

        let handle = tokio::spawn(async move {
            // Acquire semaphore — this gates how many connects run at once
            let permit = sem.acquire_owned().await.unwrap();

            // Rate limit
            rl.acquire().await;

            // Fast connect check
            let is_open = try_connect_with_retries(&ip, port, timeout_ms, retries).await;

            // Release the semaphore IMMEDIATELY so other ports can be scanned
            drop(permit);

            if is_open {
                open_count.fetch_add(1, Ordering::Relaxed);

                if banner_grab {
                    // Spawn banner grabbing as a SEPARATE task — does NOT hold the semaphore
                    let ip2 = ip.clone();
                    let templates2 = templates.clone();
                    let open_ports2 = open_ports.clone();
                    let bh = tokio::spawn(async move {
                        let result = grab_banner(&ip2, port, timeout_ms, &templates2).await;

                        let tech_str = if result.technology.is_empty() {
                            "\x1b[90munknown\x1b[0m".to_string()
                        } else {
                            format!("\x1b[36m{}\x1b[0m", result.technology.join(", "))
                        };

                        eprintln!("   \x1b[32m[+]\x1b[0m Port \x1b[1m{:<5}\x1b[0m open | Tech: {} | Banner: \x1b[90m{}\x1b[0m",
                            port,
                            tech_str,
                            result.banner.as_deref().unwrap_or("<no banner>")
                        );

                        open_ports2.lock().await.push(result);
                    });
                    banner_handles.lock().await.push(bh);
                } else {
                    let result = PortResult {
                        port,
                        state: "open".to_string(),
                        banner: None,
                        technology: Vec::new(),
                        service: None,
                        version: None,
                        tls: false,
                        tls_cn: None,
                    };
                    eprintln!("   \x1b[32m[+]\x1b[0m Port \x1b[1m{:<5}\x1b[0m open",
                        port);
                    open_ports.lock().await.push(result);
                }
            }

            scanned_count.fetch_add(1, Ordering::Relaxed);

            // Periodically save state
            {
                let mut list = scanned_list.lock().await;
                list.push(port);

                let count = scanned_count.load(Ordering::Relaxed);
                if count % 500 == 0 && !resume_file.is_empty() {
                    let open_list: Vec<u16> = open_ports.lock().await.iter().map(|p| p.port).collect();
                    let state = ScanState {
                        host: host.clone(),
                        scanned_ports: list.clone(),
                        open_ports: open_list,
                        timestamp: chrono_now(),
                    };
                    let _ = save_state(&resume_file, &state);
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all connect-check tasks to complete
    for handle in handles {
        let _ = handle.await;
    }

    // Wait for all in-flight banner grabs to finish
    let bhs: Vec<_> = banner_handles.lock().await.drain(..).collect();
    for bh in bhs {
        let _ = bh.await;
    }

    // Cancel progress reporter
    progress_handle.abort();

    // Save final state
    if !req.resume_file.is_empty() {
        let scanned = scanned_list.lock().await.clone();
        let open_list: Vec<u16> = open_ports.lock().await.iter().map(|p| p.port).collect();
        let final_state = ScanState {
            host: req.host.clone(),
            scanned_ports: scanned,
            open_ports: open_list,
            timestamp: chrono_now(),
        };
        let _ = save_state(&req.resume_file, &final_state);
    }

    let elapsed = start.elapsed();
    let open = open_ports.lock().await.clone();

    eprintln!("[*] Scan completed. {} open ports found in {:.2}s", open.len(), elapsed.as_secs_f64());

    // TTL-based OS detection: sample TTL from first open port connection
    let (os_hint, ttl_val) = detect_os_from_ttl(&target_ip).await;

    Ok(ScanResult {
        hostname: req.host.clone(),
        ips,
        rdns: rdns_map,
        open_ports: open,
        scan_time_ms: elapsed.as_millis() as u64,
        total_scanned: scanned_count.load(Ordering::Relaxed),
        scan_mode: "connect".to_string(),
        os_hint,
        ttl: ttl_val,
    })
}

/// Try to connect to a port with retries.
async fn try_connect_with_retries(ip: &str, port: u16, timeout_ms: u64, retries: u32) -> bool {
    let addr = format!("{}:{}", ip, port);
    let dur = Duration::from_millis(timeout_ms);

    for attempt in 0..retries {
        match timeout(dur, TcpStream::connect(&addr)).await {
            Ok(Ok(_stream)) => {
                return true;
            }
            Ok(Err(_)) => {
                // Connection refused = port is closed
                return false;
            }
            Err(_) => {
                // Timeout = possibly filtered, retry with backoff
                if attempt + 1 < retries {
                    let backoff = Duration::from_millis(100 * (attempt as u64 + 1));
                    debug!("Port {} timeout, retrying in {:?}...", port, backoff);
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
    false
}

/// Resolve hostname to IP addresses.
fn resolve_host(host: &str) -> Result<Vec<String>, String> {
    // Check if it's already an IP
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(vec![host.to_string()]);
    }

    let addr = format!("{}:0", host);
    match addr.to_socket_addrs() {
        Ok(addrs) => {
            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            if ips.is_empty() {
                Err(format!("Could not resolve host: {}", host))
            } else {
                Ok(ips)
            }
        }
        Err(e) => Err(format!("DNS resolution failed for {}: {}", host, e)),
    }
}

/// Attempt reverse DNS lookup for an IP address.
fn reverse_dns_lookup(ip: &str) -> Option<String> {
    use std::net::IpAddr;
    let ip_addr: IpAddr = ip.parse().ok()?;
    // Use the system resolver — construct in-addr.arpa for PTR
    // std::net doesn't expose PTR directly, so we do a best-effort approach
    match ip_addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let ptr = format!(
                "{}.{}.{}.{}.in-addr.arpa:0",
                octets[3], octets[2], octets[1], octets[0]
            );
            if let Ok(mut addrs) = ptr.to_socket_addrs() {
                addrs.next().map(|a| a.ip().to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Detect OS family from TTL of a TCP connection.
/// Maps TTL ranges to OS families:
///   64  → Linux / macOS / BSD
///   128 → Windows
///   255 → Cisco / Network devices
///   32  → Older Windows / Embedded
async fn detect_os_from_ttl(ip: &str) -> (Option<String>, Option<u32>) {
    // Try a quick connect to port 80 or 443 to read TTL
    for port in &[80, 443] {
        let addr = format!("{}:{}", ip, port);
        let dur = Duration::from_millis(2000);
        if let Ok(Ok(stream)) = timeout(dur, TcpStream::connect(&addr)).await {
            // Read TTL from the socket
            if let Ok(std_stream) = stream.into_std() {
                if let Ok(ttl) = std_stream.ttl() {
                    let os = match ttl {
                        0..=32 => "Embedded / Older Windows",
                        33..=64 => "Linux / macOS / BSD",
                        65..=128 => "Windows",
                        129..=255 => "Cisco / Network Device",
                        _ => "Unknown",
                    };
                    return (Some(os.to_string()), Some(ttl));
                }
            }
        }
    }
    (None, None)
}

/// Simple timestamp without chrono dependency.
fn chrono_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_ip() {
        let result = resolve_host("127.0.0.1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["127.0.0.1"]);
    }

    #[test]
    fn test_resolve_localhost() {
        let result = resolve_host("localhost");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_connect_closed_port() {
        // Port 1 is almost certainly not open
        let result = try_connect_with_retries("127.0.0.1", 1, 500, 1).await;
        assert!(!result);
    }
}
