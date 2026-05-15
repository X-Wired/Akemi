pub mod auth_engine;
pub mod ca;
pub mod capture;
pub mod cli;
pub mod error;
pub mod proxy;
pub mod report;
pub mod stdin;
pub mod types;

// Re-export key types for external consumers (e.g., the Go wrapper via JSON).
pub use auth_engine::{AuthEngine, ExtractedState, is_csrf_like};
pub use ca::CertificateAuthority;
pub use capture::{CaptureGraph, CaptureOptions, CaptureStore, CapturedExchange};
pub use error::DothoundResult;
pub use proxy::ProxyServer;
pub use stdin::{
    StdinCommand, StdinOptions, StdinResponse, StdinSummary, execute_start_proxy, run_stdin_mode,
    shutdown_daemon,
};
pub use types::{LoginInput, parse_login_endpoint};
