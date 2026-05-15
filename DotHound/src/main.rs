mod auth_engine;
mod ca;
mod capture;
mod cli;
mod error;
mod proxy;
mod report;
mod stdin;
mod types;

#[tokio::main]
async fn main() {
    // rustls 0.23 requires an explicit crypto provider.
    // aws-lc-rs is the default backend — install it before any TLS operations.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("dothound {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("DotHound {}", env!("CARGO_PKG_VERSION"));
        println!("Usage: dothound [--stdin | --daemon | --version]");
        return;
    }

    // If --stdin is passed, run in JSON stdin/stdout mode (for Akemi integration).
    if args.iter().any(|arg| arg == "--stdin") {
        if let Err(error) = stdin::run_stdin_mode().await {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
        return;
    }

    // If --daemon is passed, start the proxy and wait for shutdown signal.
    if args.iter().any(|arg| arg == "--daemon") {
        if let Err(error) = daemon_mode().await {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
        return;
    }

    if let Err(error) = cli::run().await {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

/// Daemon mode: start a proxy, output its address, then wait for
/// a shutdown JSON command on stdin.
async fn daemon_mode() -> crate::error::DothoundResult<()> {
    use crate::stdin::{StdinCommand, StdinOptions};

    // Start the proxy with default options.
    let options = StdinOptions {
        include_secrets: std::env::var("DOTHOUND_CAPTURE_SECRETS")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false),
        max_body_capture_bytes: 64 * 1024,
    };

    let response = stdin::execute_start_proxy(options).await;
    let json = serde_json::to_string(&response)?;
    println!("{json}");

    if response.status != "ok" {
        std::process::exit(1);
    }

    // Wait for a shutdown command on stdin.
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;

    let command: StdinCommand =
        serde_json::from_str(&input).map_err(|e| format!("Failed to parse command: {e}"))?;

    match command {
        StdinCommand::Shutdown => {
            stdin::shutdown_daemon().await?;
        }
        _ => {
            eprintln!("Daemon mode only accepts 'shutdown' command");
            std::process::exit(1);
        }
    }

    Ok(())
}
