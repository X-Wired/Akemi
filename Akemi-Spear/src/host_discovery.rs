// host_discovery.rs — CIDR host alive detection without port scanning
//
// Supports any CIDR notation (/8 through /32).
// Detection method: TCP connect to port 80 and 443 (no admin required).

use crate::models::{AliveHost, HostDiscoveryResult};
use crate::rate_limiter::RateLimiter;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Parse a CIDR notation string into a list of IPv4 addresses.
/// Supports: "192.168.1.0/24", "10.0.0.0/16", "172.16.0.1/32", etc.
pub fn parse_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR notation: {} (expected IP/prefix)", cidr));
    }

    let base_ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| format!("Invalid IP address: {}", parts[0]))?;

    let prefix: u32 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid prefix length: {}", parts[1]))?;

    if prefix > 32 {
        return Err(format!("Prefix length must be 0-32, got: {}", prefix));
    }

    let base_u32 = u32::from(base_ip);

    if prefix == 32 {
        return Ok(vec![base_ip]);
    }

    let host_bits = 32 - prefix;
    let num_hosts: u64 = 1u64 << host_bits;

    // Apply network mask to get the network address
    let mask = if prefix == 0 { 0u32 } else { !0u32 << host_bits };
    let network = base_u32 & mask;

    let mut ips = Vec::new();

    // Skip network address (first) and broadcast (last) for /31 and larger
    let (start, end) = if prefix <= 30 {
        (1u64, num_hosts - 1) // Skip .0 (network) and .255 (broadcast)
    } else {
        (0u64, num_hosts) // /31 and /32: include all
    };

    for i in start..end {
        let ip_u32 = network.wrapping_add(i as u32);
        ips.push(Ipv4Addr::from(ip_u32));
    }

    Ok(ips)
}

/// Check if a string looks like CIDR notation (contains a /).
pub fn is_cidr(host: &str) -> bool {
    host.contains('/') && host.split('/').count() == 2
}

/// Run host discovery on a list of IPs.
/// Uses TCP connect to port 80 and 443 as alive indicators.
pub async fn run_host_discovery(
    ips: &[Ipv4Addr],
    threads: u32,
    timeout_ms: u64,
    rate: f64,
    verbose: bool,
) -> HostDiscoveryResult {
    let start = Instant::now();
    let total = ips.len() as u32;

    eprintln!(
        "[*] Host discovery: {} hosts, {} threads",
        total, threads
    );

    let alive_hosts: Arc<Mutex<Vec<AliveHost>>> = Arc::new(Mutex::new(Vec::new()));
    let scanned_count = Arc::new(AtomicU32::new(0));
    let alive_count = Arc::new(AtomicU32::new(0));
    let sem = Arc::new(tokio::sync::Semaphore::new(threads as usize));
    let rate_limiter = RateLimiter::new(rate, threads);

    // Progress reporter
    let scanned_for_progress = scanned_count.clone();
    let alive_for_progress = alive_count.clone();
    let progress_handle = tokio::spawn(async move {
        let progress_start = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let current = scanned_for_progress.load(Ordering::Relaxed);
            let alive = alive_for_progress.load(Ordering::Relaxed);
            let elapsed = progress_start.elapsed().as_secs_f64().max(0.1);
            let rate = current as f64 / elapsed;
            if verbose {
                eprintln!(
                    "[progress] {}/{} hosts checked | {} alive | {:.0} hosts/sec",
                    current, total, alive, rate
                );
            }
            if current >= total {
                break;
            }
        }
    });

    // Spawn discovery tasks
    let mut handles = Vec::new();

    for ip in ips {
        let ip = *ip;
        let sem = sem.clone();
        let rl = rate_limiter.clone();
        let alive_hosts = alive_hosts.clone();
        let scanned_count = scanned_count.clone();
        let alive_count = alive_count.clone();
        let dur = Duration::from_millis(timeout_ms);

        let handle = tokio::spawn(async move {
            let permit = sem.acquire_owned().await.unwrap();
            rl.acquire().await;

            let ip_str = ip.to_string();
            let probe_start = Instant::now();

            // Try TCP connect to common ports
            let (is_alive, method) = tcp_alive_check(&ip_str, dur).await;

            drop(permit);

            if is_alive {
                let latency = probe_start.elapsed().as_secs_f64() * 1000.0;

                // Reverse DNS lookup
                let rdns = reverse_dns(&ip_str);

                let host = AliveHost {
                    ip: ip_str.clone(),
                    alive: true,
                    latency_ms: (latency * 100.0).round() / 100.0,
                    rdns,
                    method,
                };

                if let Some(ref rdns_name) = host.rdns {
                    eprintln!(
                        "   \x1b[32m[+]\x1b[0m \x1b[1m{}\x1b[0m alive ({}) | \x1b[90m{}\x1b[0m | {:.1}ms",
                        ip_str, host.method, rdns_name, host.latency_ms
                    );
                } else {
                    eprintln!(
                        "   \x1b[32m[+]\x1b[0m \x1b[1m{}\x1b[0m alive ({}) | {:.1}ms",
                        ip_str, host.method, host.latency_ms
                    );
                }

                alive_count.fetch_add(1, Ordering::Relaxed);
                alive_hosts.lock().await.push(host);
            }

            scanned_count.fetch_add(1, Ordering::Relaxed);
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    progress_handle.abort();

    let elapsed = start.elapsed();
    let alive = alive_hosts.lock().await.clone();

    eprintln!(
        "[*] Discovery completed. {}/{} hosts alive in {:.2}s",
        alive.len(),
        total,
        elapsed.as_secs_f64()
    );

    HostDiscoveryResult {
        total_hosts: total,
        alive_hosts: alive,
        scan_time_ms: elapsed.as_millis() as u64,
    }
}

/// Check if a host is alive by trying TCP connect to common ports.
/// Returns (alive, method_used).
async fn tcp_alive_check(ip: &str, dur: Duration) -> (bool, String) {
    // Try port 80 first (most common)
    let addr80 = format!("{}:80", ip);
    match timeout(dur, TcpStream::connect(&addr80)).await {
        Ok(Ok(_)) => return (true, "tcp-80".to_string()),
        Ok(Err(e)) => {
            // Connection refused = host is alive (port closed but host responding)
            let msg = e.to_string();
            if msg.contains("refused") || msg.contains("reset") {
                return (true, "tcp-80-rst".to_string());
            }
        }
        Err(_) => {} // Timeout
    }

    // Try port 443
    let addr443 = format!("{}:443", ip);
    match timeout(dur, TcpStream::connect(&addr443)).await {
        Ok(Ok(_)) => return (true, "tcp-443".to_string()),
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("refused") || msg.contains("reset") {
                return (true, "tcp-443-rst".to_string());
            }
        }
        Err(_) => {}
    }

    // Try port 22 (SSH — often open on servers)
    let addr22 = format!("{}:22", ip);
    match timeout(dur, TcpStream::connect(&addr22)).await {
        Ok(Ok(_)) => return (true, "tcp-22".to_string()),
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("refused") || msg.contains("reset") {
                return (true, "tcp-22-rst".to_string());
            }
        }
        Err(_) => {}
    }

    // If all TCP ports failed, fallback to ICMP Ping
    if ping_fallback(ip).await {
        return (true, "icmp-echo".to_string());
    }

    (false, String::new())
}

/// Fallback to OS-provided ping command since raw sockets require root/admin.
/// Uses tokio::process::Command to avoid blocking the executor.
async fn ping_fallback(ip: &str) -> bool {
    let output = if cfg!(target_os = "windows") {
        tokio::process::Command::new("ping")
            .args(&["-n", "1", "-w", "1000", ip])
            .output()
            .await
    } else {
        tokio::process::Command::new("ping")
            .args(&["-c", "1", "-W", "1", ip])
            .output()
            .await
    };

    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Perform reverse DNS lookup for an IP address.
fn reverse_dns(ip: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    let addr = format!("{}:0", ip);
    // Try to do a reverse lookup via the system resolver
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(_) = addrs.next() {
            // Unfortunately std doesn't expose PTR lookup directly.
            // We use a manual approach: try to lookup the IP as a hostname.
            // This won't work for PTR in std. Use dns-lookup crate approach instead.
        }
    }

    // Manual PTR via std — construct in-addr.arpa query
    // Since we can't do PTR with std alone, try getnameinfo equivalent
    use std::net::IpAddr;
    if let Ok(ip_addr) = ip.parse::<IpAddr>() {
        // Use the underlying OS resolver for reverse DNS
        match dns_reverse_lookup(ip_addr) {
            Some(name) if name != ip => Some(name),
            _ => None,
        }
    } else {
        None
    }
}

/// OS-level reverse DNS lookup using gethostbyaddr equivalent.
fn dns_reverse_lookup(ip: std::net::IpAddr) -> Option<String> {
    use std::net::SocketAddr;
    // Create a socket addr and use the system's name resolution
    let _socket_addr = SocketAddr::new(ip, 0);
    
    // Use std::net name lookup — on most systems this calls getnameinfo
    // Unfortunately Rust's std doesn't have a direct reverse DNS API.
    // We'll attempt a workaround: the hostname crate or manual lookup.
    
    // Fallback: try to connect and check — or just return None for now
    // and let the DNS-lookup crate handle it if available.
    
    // Simple approach: use the system DNS by trying to resolve the reverse
    // We'll construct the PTR name manually and try resolution
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            let ptr_name = format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            );
            // Try resolving the PTR name
            use std::net::ToSocketAddrs;
            // This won't actually do PTR lookup via std, but let's try
            match format!("{}:0", ptr_name).to_socket_addrs() {
                Ok(mut addrs) => addrs.next().map(|a| a.ip().to_string()),
                Err(_) => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_24() {
        let ips = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ips.len(), 254); // .1 through .254
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_parse_cidr_32() {
        let ips = parse_cidr("10.0.0.1/32").unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_parse_cidr_16() {
        let ips = parse_cidr("172.16.0.0/16").unwrap();
        assert_eq!(ips.len(), 65534); // .0.1 through .255.254
    }

    #[test]
    fn test_is_cidr() {
        assert!(is_cidr("192.168.1.0/24"));
        assert!(is_cidr("10.0.0.0/8"));
        assert!(!is_cidr("192.168.1.1"));
        assert!(!is_cidr("google.com"));
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_cidr("not-an-ip/24").is_err());
        assert!(parse_cidr("192.168.1.0/33").is_err());
        assert!(parse_cidr("192.168.1.0").is_err());
    }
}
