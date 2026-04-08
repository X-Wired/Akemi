# Akemi - Commands Reference

This document provides a comprehensive guide to all possible attack scenarios, operational modes, and options available in the Akemi framework. 

---

## 1. Attack Surface Discovery

**Full Website Crawl & Scrape**
Run a complete discovery loop including Deep Web crawling, Javascript analysis, parameter extraction, and data scraping.
```bash
Akemi.exe -u https://target.com --crawl --depth 3 --params --js --scrape
```

**Stealth Parameter Mining**
Focus entirely on hidden parameters in Javascript, forms, and JSON routes without active probing.
```bash
Akemi.exe -u https://target.com --params
```
*Optional parameters*: 
- `-params-js=false` (Disable JS parameter parsing)
- `-params-brute=true` (Enable aggressive अर्जुन (Arjun) style wordlist brute-forcing)

---

## 2. Advanced Subdomain Enumeration

**Passive & Active Subdomain Discovery**
Query Certificate Transparency logs (`crt.sh`) combined with a wordlist brute-force to identify all subdomains.
```bash
Akemi.exe -u target.com --sub --sub-w subdomains.txt --sub-threads 50
```

**Subdomain Permutation**
Generate permutations iteratively based on existing successful hits (e.g. `dev.target.com` -> `dev01.target.com`).
```bash
Akemi.exe -u target.com --sub --sub-crtsh --sub-permute
```

---

## 3. High-Speed Infrastructure Scanning 

**Standard Port Scan**
Scan multiple IP addresses or domains loaded from a file using the internal threaded engine.
```bash
Akemi.exe --targets scope.txt --port-scan -p 80,443,8080,8443 --scanthreads 200
```

**SYN Stealth Scan**
Requires root/Administrator privileges and Npcap/libpcap. Significantly limits connection overhead.
```bash
Akemi.exe --targets scope.txt --port-scan -p 1-65535 --syn --rate 3000 --randomize
```

---

## 4. Exploit-DB Correlation

**Automated Service Mapping**
When performing a port scan, correlate identified technology banners automatically with the ExploitDB dataset.
```bash
Akemi.exe --targets targets.txt --port-scan --exploit-lookup --exploit-lookup-max 5
```
*Note*: This flags known CVEs and offline databases dynamically based on the exact version gathered by the scanner.

---

## 5. Vulnerability Validation (Template Engine)

**Run All High-Impact Templates**
Launch the YAML-based probe engine to test for common vulnerabilities targeting the URL queue.
```bash
Akemi.exe -u https://target.com --vuln-check
```

**Scan via Tags**
Filter templates specifically to test for a certain bug class (like SQLi or Local File Inclusion).
```bash
Akemi.exe -u https://target.com --vuln-check --vuln-check-tags sqli,lfi,xss
```

**Check Available Templates**
List all dynamically loaded YAML templates available in the `./probes/` directory.
```bash
Akemi.exe --vuln-check-list
```

---

## 6. Target Dorking and OSINT

**Automated Search Engine Dorking**
Hunt for vulnerable endpoints aggressively using DuckDuckGo or Google as the backbone.
```bash
Akemi.exe --dork "site:target.com ext:php inurl:id=" --engine duckduckgo
```

**Template Dorking Automation**
Run large dorking lists (from a text file) and extract matching domains automatically.
```bash
Akemi.exe --dork-file dorks.txt --keywords "admin,login,dashboard" --scraping
```

---

## 7. Custom Fuzzing Pipelines

**Standard Directory Fuzzing**
Fuzz hidden routes or APIs.
```bash
Akemi.exe -u "https://target.com/FUZZ" -w wordlist.txt -t 5 -c 30
```

**POST Request Fuzzing**
Send POST payloads to an API endpoint for injection discovery.
```bash
Akemi.exe -u "https://target.com/api/login" -m POST -d "user=admin&pass=FUZZ" -w passwords.txt
```

---

## 8. Reporting & Graph Visualization

**Generate Full Interactive Dashboard**
Save the final map as HTML, JSON datasets, and an interactive relational graph for reporting.
```bash
Akemi.exe -u https://target.com --crawl --params --graph --report --report-dir ./results
```

---

## 🔧 Global Tuning & Configuration

You can seamlessly modify the execution context utilizing these options:

- `-proxy "http://127.0.0.1:8080"` : Route traffic through Burp Suite, ZAP, or Tor (SOCKS5).
- `-timeout 15` : Modify network timeout buffers (Seconds).
- `-quiet` or `-q` : Disable decorative ASCII art and headers for seamless terminal pipelines (e.g. `| grep finding`).
