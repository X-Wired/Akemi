use std::env;
use std::path::PathBuf;

fn main() {
    // Windows-only: link against Npcap/WinPcap libraries for raw socket support
    #[cfg(target_os = "windows")]
    {
        // Get the directory where Cargo.toml is located
        let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let lib_path = PathBuf::from(dir);

        // Tell Cargo to search for native libraries in the project root (where Packet.lib is)
        println!("cargo:rustc-link-search=native={}", lib_path.display());

        // Re-run this build script if Packet.lib or wpcap.lib changes
        println!("cargo:rerun-if-changed=Packet.lib");
        println!("cargo:rerun-if-changed=wpcap.lib");
    }

    // Suppress unused variable warning on non-Windows
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (env::var("CARGO_MANIFEST_DIR"), PathBuf::new());
    }
}
