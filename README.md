![Akemi Logo](Pictures/CyberHuntress.png)

# Akemi: Surface Map Attack Framework

**Akemi** (Akemi Build 1.0.0) is a modular, high-performance Surface Map Attack Framework designed for comprehensive attack surface mapping and systematic vulnerability validation. It provides a terminal-first workflow that bridges the gap between massive reconnaissance and actionable exploitation.

The framework integrates high-speed network triage, deep web discovery, and a robust verification engine into a single, cohesive command-line environment.

---

## ⚡ Key Highlights

###  Akemi-Spear: The Reconnaissance Edge 
At the heart of Akemi lies **Akemi-Spear**, a high-performance Rust reconnaissance engine. It is built for speed and stealth, handling infrastructure triage tasks that traditional tools struggle with at scale:
- **High-Speed Host Discovery**: Multi-threaded sweep and SYN scanning capabilities.
- **Service Fingerprinting**: Efficient banner collection and service-oriented triage.
- **Port Scanning**: Template-based and customizable scanning logic optimized for reliability.

###  YAML-Driven Vulnerability Validation (Based on Nuclei)
Akemi moves beyond simple discovery with its **Probe Engine**. It uses a flexible, YAML-driven approach to validate vulnerabilities across your attack surface:
- **Customizable Templates**: The `probes/` directory contains active checks for SQLi, RCE, SSRF, and deserialization.
- **Protocol Agnostic**: Validate findings across HTTP, DNS, and more using structured logic.

---

##  Core Capabilities

- **Attack Surface Mapping**: Automated web crawling, subdomain enumeration, and endpoint extraction.
- **Dynamic Parameter Mining**: Deep discovery of parameters from URLs, forms, JSON, and JavaScript files.
- **JavaScript Analysis**: Scrutinizes JS files for endpoints, secrets, and sensitive logic.
- **ExploitDB Correlation**: Correlate identified services and versions with the ExploitDB dataset to flag potential public exploits.
- **Relational Graphing**: Export scan results as interactive HTML or DOT graphs to visualize the attack path.
- **Comprehensive Reporting**: Generate detailed HTML and JSON reports for every engagement.

---

##  Repository Layout

```text
cmd/
  Akemi/                CLI Entrypoint
internal/
  app/                  Core framework logic
  recon/                Crawl, scrape, JS, and subdomain analysis
  vuln/                 Structured YAML probe engine
  exploit/              ExploitDB matching engine and datasets
  reporting/            HTML/JSON report and graph generators
Akemi-Spear/           High-performance Rust recon engine
config/                Runtime and proxy configurations
probes/                YAML vulnerability templates
wordlists/             Curated dork packs and dictionaries
```

---

##  Quick Start

### Build Instructions

Use the provided PowerShell script to build optimized binaries for Windows and Linux:

```powershell
./build.ps1
```
Or see the release page for pre-built binaries.

**Requirements:**
- Go `1.25.0` or higher
- Rust stable toolchain

---

##  Common Workflows

### 1. Full Surface Mapping
Discover everything on a target, including parameters and JavaScript endpoints:
```bash
Akemi.exe -u https://target.com --crawl --depth 3 --params --js --scrape --graph --report-dir ./results
```

### 2. Infrastructure Triage & Port Scanning
Leverage Akemi-Spear for high-speed scanning:
```bash
Akemi.exe --targets targets.txt --port-scan -p 80,443,8080 --rate 1000
```

### 3. Vulnerability Probing
Validate high-impact vulnerabilities with structured templates:
```bash
Akemi.exe -u https://target.com --vuln-check --vuln-check-tags sqli,lfi
```

### 4. Relational Graph Generation
Visualize the discovered surface and its connections:
```bash
Akemi.exe -u https://target.com --crawl --graph --report-dir ./results
```
![Akemi Surface Map](Pictures/Akemi_Surface_Map.png)
---

## License
Your are free to use this tool for educational purposes only. Do not use this tool for any illegal activities. Also, you dont have the authorizacion to distribuite this software. nor sell it, you can fork it and modify it for your own purposes, share with community and more. 


