#!/bin/bash

# Akemi: Surface Map Attack Framework - Linux Installer
# This script automates the environment setup and compilation of Akemi.

set -e

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "   _____   __                         .__ "
echo "  /  _  \ |  | __ ____   _____        |__|"
echo " /  /_\  \|  |/ // __ \ /     \       |  |"
echo "/    |    \    <|  ___/|  Y Y  \      |  |"
echo "\____|__  /__|_ \\___  >__|_|  / /\   |__|"
echo "        \/     \/    \/      \/  )/       "
echo -e "${NC}"
echo -e "${GREEN}[*] Starting Akemi Linux Installer...${NC}"

# 1. Check OS
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}[!] This script is intended for Linux systems.${NC}"
    exit 1
fi

# 2. Prerequisites Check (Sudo)
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}[!] Some steps might require sudo privileges for package installation.${NC}"
fi

# 3. Detect Package Manager & Install Dependencies
echo -e "${BLUE}[*] Checking system dependencies...${NC}"

install_pkg() {
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y build-essential libpcap-dev libssl-dev pkg-config git curl
    elif command -v dnf &> /dev/null; then
        sudo dnf groupinstall -y "Development Tools"
        sudo dnf install -y libpcap-devel openssl-devel pkgconfig git curl
    elif command -v pacman &> /dev/null; then
        sudo pacman -Sy --noconfirm base-devel libpcap openssl pkgconf git curl
    else
        echo -e "${YELLOW}[!] Unknown package manager. Please ensure libpcap, openssl, and build tools are installed.${NC}"
    fi
}

install_pkg

# 4. Toolchain: Go
echo -e "${BLUE}[*] Checking Go toolchain...${NC}"
GO_REQUIRED="1.25.0"

check_go() {
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        echo -e "${GREEN}[+] Found Go version: $GO_VERSION${NC}"
        # Simplified version comparison
        if [[ "$GO_VERSION" < "1.22.0" ]]; then
            echo -e "${YELLOW}[!] Go version is older than 1.22. It is recommended to upgrade.${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Go not found. Attempting to install latest version...${NC}"
        # Optional: Auto-install Go via official tarball could be added here
        echo -e "${RED}[!] Please install Go $GO_REQUIRED or higher: https://go.dev/doc/install${NC}"
        exit 1
    fi
}

check_go

# 5. Toolchain: Rust
echo -e "${BLUE}[*] Checking Rust toolchain...${NC}"
if command -v cargo &> /dev/null; then
    echo -e "${GREEN}[+] Found Rust/Cargo.${NC}"
else
    echo -e "${YELLOW}[!] Rust not found. Installing via rustup...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

# 6. Build Preparation
echo -e "${BLUE}[*] Preparing build environment...${NC}"
mkdir -p bin/linux

# 7. Build Akemi (Go)
echo -e "${BLUE}[*] Building Akemi (Core Go Engine)...${NC}"
go build -v -o bin/linux/Akemi ./cmd/Akemi
echo -e "${GREEN}[+] Akemi binary created at bin/linux/Akemi${NC}"

# 8. Build Akemi-Spear (Rust)
echo -e "${BLUE}[*] Building Akemi-Spear (Recon Engine)...${NC}"
cd Akemi-Spear
cargo build --release --features "syn-scan,tls-native"
cd ..
cp Akemi-Spear/target/release/Akemi-Spear bin/linux/
echo -e "${GREEN}[+] Akemi-Spear binary created at bin/linux/Akemi-Spear${NC}"

# 9. Installation Logic
echo -e ""
read -p "Do you want to symlink binaries to /usr/local/bin? [y/N] " install_choice
if [[ "$install_choice" =~ ^[Yy]$ ]]; then
    sudo ln -sf "$(pwd)/bin/linux/Akemi" /usr/local/bin/akemi
    sudo ln -sf "$(pwd)/bin/linux/Akemi-Spear" /usr/local/bin/akemi-spear
    echo -e "${GREEN}[+] Symlinks created! You can now run 'akemi' and 'akemi-spear' from anywhere.${NC}"
fi

echo -e "\n${GREEN}[*] Installation Complete!${NC}"
echo -e "Binaries are located in: ${BLUE}$(pwd)/bin/linux${NC}"
echo -e "Wordlists are located in: ${BLUE}$(pwd)/wordlists${NC}"
echo -e "Probes are located in: ${BLUE}$(pwd)/probes${NC}"
echo -e "\nHappy Hunting!"
