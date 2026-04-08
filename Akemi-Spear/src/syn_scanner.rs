// syn_scanner.rs — Raw SYN scanning using pnet (masscan-style async model)
//
// This entire module is conditionally compiled behind the `syn-scan` feature flag.
// Build with: cargo build --features syn-scan
//
// Without the feature, SYN scan requests will gracefully fall back to connect scanning.

#[cfg(feature = "syn-scan")]
pub mod inner {
    use crate::banner_grabber::{grab_banner, load_tcp_templates};
    use crate::models::{PortResult, ScanRequest, ScanResult, ScanState};
    use crate::rate_limiter::RateLimiter;
    use crate::resume::{filter_remaining_ports, load_state, save_state};
    use log::{error, info, warn};
    use rand::seq::SliceRandom;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::Mutex;

    /// Check if raw socket creation is possible.
    pub fn check_raw_socket_available() -> bool {
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol::Ipv4};

        let protocol = TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
        transport_channel(256, protocol).is_ok()
    }

    /// Attempt a SYN scan. Falls back to connect scan if raw sockets are unavailable.
    pub async fn run_syn_scan(req: &ScanRequest) -> Result<ScanResult, String> {
        if !check_raw_socket_available() {
            warn!("[!] Raw sockets unavailable (run as admin/root, or install Npcap on Windows)");
            warn!("[!] Falling back to connect scan...");
            return crate::scanner::run_connect_scan(req).await;
        }

        info!(
            "[*] SYN scan mode on {} — {} ports",
            req.host,
            req.ports.len()
        );
        let start = Instant::now();

        // Resolve host
        let ips = resolve_host_syn(&req.host)?;
        let target_ip = ips[0].clone();

        // Load templates for enrichment phase
        let tcp_templates = if req.banner_grab {
            load_tcp_templates(&req.probe_templates_dir)
        } else {
            Vec::new()
        };

        // Load resume state and filter ports
        let state = load_state(&req.resume_file);
        let mut ports = filter_remaining_ports(&req.ports, &state);

        if req.randomize {
            let mut rng = rand::rng();
            ports.shuffle(&mut rng);
        }

        let total_ports = ports.len() as u32;
        let rate_limiter = RateLimiter::new(req.rate, req.threads);

        // Phase 1: SYN discovery
        eprintln!("[*] Phase 1: SYN discovery ({} ports)...", total_ports);
        let open_port_numbers = syn_discovery(&target_ip, &ports, req.timeout_ms, &rate_limiter).await;
        eprintln!(
            "[*] Phase 1 complete: {} open ports discovered",
            open_port_numbers.len()
        );

        // Phase 2: Banner enrichment
        let mut open_ports = Vec::new();
        if req.banner_grab && !open_port_numbers.is_empty() {
            eprintln!(
                "[*] Phase 2: Banner grabbing {} open ports...",
                open_port_numbers.len()
            );
            let sem = Arc::new(tokio::sync::Semaphore::new(req.threads as usize));
            let results: Arc<Mutex<Vec<PortResult>>> = Arc::new(Mutex::new(Vec::new()));
            let mut handles = Vec::new();

            for port in &open_port_numbers {
                let permit = sem.clone().acquire_owned().await.unwrap();
                let ip = target_ip.clone();
                let timeout_ms = req.timeout_ms;
                let templates = tcp_templates.clone();
                let results = results.clone();
                let p = *port;

                let handle = tokio::spawn(async move {
                    let result = grab_banner(&ip, p, timeout_ms, &templates).await;
                    let tech_str = if result.technology.is_empty() { 
                        "\x1b[90munknown\x1b[0m".to_string() 
                    } else { 
                        format!("\x1b[36m{}\x1b[0m", result.technology.join(", ")) 
                    };

                    eprintln!("   \x1b[32m[+]\x1b[0m Port \x1b[1m{:<5}\x1b[0m open | Tech: {} | Banner: \x1b[90m{}\x1b[0m",
                        p,
                        tech_str,
                        result.banner.as_deref().unwrap_or("<no banner>")
                    );
                    results.lock().await.push(result);
                    drop(permit);
                });
                handles.push(handle);
            }

            for handle in handles {
                let _ = handle.await;
            }

            open_ports = results.lock().await.clone();
        } else {
            for port in &open_port_numbers {
                open_ports.push(PortResult {
                    port: *port,
                    state: "open".to_string(),
                    banner: None,
                    technology: Vec::new(),
                    service: None,
                    version: None,
                    tls: false,
                    tls_cn: None,
                });
            }
        }

        let elapsed = start.elapsed();
        eprintln!(
            "[*] SYN scan completed. {} open ports in {:.2}s",
            open_ports.len(),
            elapsed.as_secs_f64()
        );

        // Save final state
        if !req.resume_file.is_empty() {
            let final_state = ScanState {
                host: req.host.clone(),
                scanned_ports: ports,
                open_ports: open_port_numbers,
                timestamp: format!("{}", elapsed.as_secs()),
            };
            let _ = save_state(&req.resume_file, &final_state);
        }

        Ok(ScanResult {
            hostname: req.host.clone(),
            ips,
            rdns: std::collections::HashMap::new(),
            open_ports,
            scan_time_ms: elapsed.as_millis() as u64,
            total_scanned: total_ports,
            scan_mode: "syn".to_string(),
            os_hint: None,
            ttl: None,
        })
    }

    /// Perform SYN discovery using pnet raw sockets.
    async fn syn_discovery(
        target_ip: &str,
        ports: &[u16],
        timeout_ms: u64,
        rate_limiter: &RateLimiter,
    ) -> Vec<u16> {
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
        use pnet::transport::{
            tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol::Ipv4,
        };

        let target: std::net::Ipv4Addr = match target_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                error!("Invalid IPv4 address for SYN scan: {}", target_ip);
                return Vec::new();
            }
        };

        let protocol = TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
        let (mut tx, mut rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => {
                error!("Failed to create raw socket: {}", e);
                return Vec::new();
            }
        };

        let open_ports: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));
        let done_sending = Arc::new(AtomicBool::new(false));
        let sent_count = Arc::new(AtomicU32::new(0));

        // Receive task
        let open_ports_rx = open_ports.clone();
        let done_rx = done_sending.clone();
        let target_for_rx = target;

        let rx_handle = std::thread::spawn(move || {
            let mut iter = tcp_packet_iter(&mut rx);
            loop {
                if done_rx.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(timeout_ms.min(3000)));
                    break;
                }
                match iter.next() {
                    Ok((packet, addr)) => {
                        if addr == std::net::IpAddr::V4(target_for_rx)
                            && packet.get_flags() & TcpFlags::SYN != 0
                            && packet.get_flags() & TcpFlags::ACK != 0
                        {
                            let port = packet.get_source();
                            let mut set = open_ports_rx.blocking_lock();
                            set.insert(port);
                        }
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        });

        // Send task
        let total = ports.len();
        for port in ports {
            rate_limiter.acquire().await;

            let mut tcp_buf = vec![0u8; 20];
            if let Some(mut tcp_packet) = MutableTcpPacket::new(&mut tcp_buf) {
                tcp_packet.set_source(49152 + (port % 16383));
                tcp_packet.set_destination(*port);
                tcp_packet.set_sequence((*port as u32) * 7919 + 1337);
                tcp_packet.set_acknowledgement(0);
                tcp_packet.set_data_offset(5);
                tcp_packet.set_flags(TcpFlags::SYN);
                tcp_packet.set_window(64240);

                let dest = std::net::IpAddr::V4(target);
                if let Err(e) = tx.send_to(tcp_packet, dest) {
                    warn!("Failed to send SYN to port {}: {}", port, e);
                }
            }

            let count = sent_count.fetch_add(1, Ordering::Relaxed) + 1;
            if count % 1000 == 0 {
                eprintln!("[progress] {}/{} | SYN packets sent", count, total);
            }
        }

        done_sending.store(true, Ordering::Relaxed);
        let _ = rx_handle.join();

        let discovered_ports = {
            let locked = open_ports.lock().await;
            locked.iter().cloned().collect()
        };

        discovered_ports
    }

    /// Resolve host for SYN scan (must be IPv4).
    fn resolve_host_syn(host: &str) -> Result<Vec<String>, String> {
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return Ok(vec![ip.to_string()]);
        }
        use std::net::ToSocketAddrs;
        let addr = format!("{}:0", host);
        match addr.to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<String> = addrs
                    .filter_map(|a| {
                        if let std::net::IpAddr::V4(v4) = a.ip() {
                            Some(v4.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
                if ips.is_empty() {
                    Err(format!("No IPv4 address found for: {}", host))
                } else {
                    Ok(ips)
                }
            }
            Err(e) => Err(format!("DNS resolution failed for {}: {}", host, e)),
        }
    }
}

// When syn-scan feature is not enabled, provide a fallback that always uses connect scan
#[cfg(not(feature = "syn-scan"))]
pub mod inner {
    use crate::models::{ScanRequest, ScanResult};
    use crate::scanner::run_connect_scan;

    pub async fn run_syn_scan(req: &ScanRequest) -> Result<ScanResult, String> {
        eprintln!("[!] SYN scan not available: akemi-scanner was built without the 'syn-scan' feature.");
        eprintln!("[!] Rebuild with: cargo build --features syn-scan");
        eprintln!("[!] (Requires Npcap on Windows, libpcap on Linux)");
        eprintln!("[!] Falling back to connect scan...");
        run_connect_scan(req).await
    }
}
