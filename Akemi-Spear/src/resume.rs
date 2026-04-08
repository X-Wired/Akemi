// resume.rs — Scan state persistence (save/load progress)
use crate::models::ScanState;
use std::collections::HashSet;
use std::fs;
use std::io;

/// Load a previously saved scan state from a JSON file.
/// Returns None if the file doesn't exist or is unreadable.
pub fn load_state(path: &str) -> Option<ScanState> {
    if path.is_empty() {
        return None;
    }
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Save scan state to a JSON file.
pub fn save_state(path: &str, state: &ScanState) -> io::Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    let data = serde_json::to_string_pretty(state)?;
    fs::write(path, data)?;
    Ok(())
}

/// Filter out already-scanned ports from the port list.
pub fn filter_remaining_ports(ports: &[u16], state: &Option<ScanState>) -> Vec<u16> {
    match state {
        Some(s) => {
            let scanned: HashSet<u16> = s.scanned_ports.iter().cloned().collect();
            ports.iter().filter(|p| !scanned.contains(p)).cloned().collect()
        }
        None => ports.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_remaining_ports() {
        let state = ScanState {
            host: "test".into(),
            scanned_ports: vec![22, 80, 443],
            open_ports: vec![22, 80],
            timestamp: "2025-01-01".into(),
        };
        let ports = vec![22, 80, 443, 8080, 3306];
        let remaining = filter_remaining_ports(&ports, &Some(state));
        assert_eq!(remaining, vec![8080, 3306]);
    }

    #[test]
    fn test_filter_no_state() {
        let ports = vec![22, 80, 443];
        let remaining = filter_remaining_ports(&ports, &None);
        assert_eq!(remaining, ports);
    }

    #[test]
    fn test_load_nonexistent() {
        let result = load_state("/nonexistent/path.json");
        assert!(result.is_none());
    }
}
