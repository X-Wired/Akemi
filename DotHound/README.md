# DotHound

**Headless login workflow capture with HTTPS MITM.**

DotHound is a command-line tool that intercepts, decrypts, and records every HTTP exchange
during an authentication workflow — so you can analyse, replay, or recreate the login flow
programmatically.

It acts as an **HTTPS-intercepting proxy** with a built-in **headless HTTP client**,
eliminating the need for a browser or manual clicking.

---

## Architecture

```
┌──────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   AuthEngine     │     │    DotHound Proxy     │     │   Real Server   │
│   (reqwest)      │────▶│    (HTTPS MITM)       │────▶│   (https://…)   │
│                  │     │                      │     │                 │
│   trusts CA ◀────│────▶│  captures everything  │◀────│                 │
└──────────────────┘     └──────┬───────────────┘     └─────────────────┘
                                │
                         ┌──────▼──────┐
                         │  JSON Graph │
                         │  .json      │
                         └─────────────┘
```

1. **CA Generation** — A fresh self-signed CA is created at startup (`.dothound/ca/dothound-ca.crt`).
2. **Proxy starts** — Listening on `127.0.0.1:<random-port>`, ready to MITM HTTPS.
3. **Headless client** — A `reqwest`-based HTTP client routes all traffic through the proxy and
   trusts the DotHound CA, so TLS decryption is transparent.
4. **Workflow execution** — The tool GETs the login page, extracts CSRF tokens, POSTs
   credentials, and follows redirects — all captured.
5. **JSON output** — A workflow graph is written to `captures/` with every exchange recorded.

---

## Installation

### Prerequisites

- **Rust** 1.85+ (edition 2024)
- A C compiler (for the `openssl`-free build via `ring`)

### Build from source

```sh
git clone https://github.com/your-org/dothound.git
cd dothound
cargo build --release
```

The binary will be at `target/release/dothound` (or `dothound.exe` on Windows).

### Quick install

```sh
cargo install --path .
```

---

## Usage

### Basic — headless login capture

```sh
dothound
```

You'll be prompted interactively:

```
DotHound 0.1.0
Headless login workflow capture with HTTPS MITM

Login endpoint: https://example.com/login
User: alice@example.com
pass: ************
```

DotHound then:

1. Generates the CA and starts the proxy.
2. Fetches the login page and extracts hidden form fields (CSRF tokens, nonces, etc.).
3. Builds a POST payload with the CSRF token + credentials + any other hidden fields.
4. Submits the form and follows redirects (up to 10).
5. Shuts down the proxy and writes the workflow graph.

```
→ Fetching login page...
  Status: 200 OK
  Extracted hidden fields:
    csrf_token = 8f3a9b2c1d4e5f6...
    return_to = /dashboard

→ Submitting login to: https://example.com/session
  Form fields:
    csrf_token = 8f3a9b2c1d4e5f6...
    username = alice@example.com
    pass = ***
  Login response: 302 Found

→ Following redirect: https://example.com/dashboard
  Status: 200 OK

Login workflow complete. Shutting down proxy...
Saved workflow graph: captures/dothound-workflow-1732765123456.json
```

---

### Capturing secrets (cookies, tokens, passwords in the clear)

By default DotHound **redacts** sensitive values — `Authorization` headers, `Set-Cookie`,
CSRF tokens, password fields in JSON bodies, etc. — replacing them with `<redacted>`.

To capture **raw values** (for full replay fidelity), set the environment variable:

```sh
# Linux / macOS
DOTHOUND_CAPTURE_SECRETS=1 dothound

# Windows PowerShell
$env:DOTHOUND_CAPTURE_SECRETS = "1"
dothound
```

Accepted values: `1`, `true`, `TRUE`, `yes`, `YES`.

---

### Installing the CA in external tools

If you want to use an external browser, `curl`, or another HTTP client through the
DotHound proxy, you must install the CA certificate so those tools trust the MITM
connection.

The CA certificate is saved to `.dothound/ca/dothound-ca.crt`.

| Platform | Install command / location |
|----------|---------------------------|
| **Windows** | `certutil -addstore Root .dothound\ca\dothound-ca.crt` |
| **macOS** | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain .dothound/ca/dothound-ca.crt` |
| **Linux (system)** | `sudo cp .dothound/ca/dothound-ca.crt /usr/local/share/ca-certificates/dothound.crt && sudo update-ca-certificates` |
| **Firefox** | Preferences → Privacy & Security → Certificates → View Certificates → Import |
| **curl** | `curl --cacert .dothound/ca/dothound-ca.crt --proxy http://127.0.0.1:<PORT> https://example.com` |

> **Note:** The CA is regenerated on every run. If you install it for external
> tools, you must re-install after each restart. The built-in headless client
> trusts the CA automatically, so this is only needed for external tools.

---

### Using a manual browser with the proxy

If you need to handle complex flows that can't be automated (WebAuthn, CAPTCHAs, MFA),
you can use the proxy with a real browser.

1. Run DotHound to generate the CA and start the proxy (press Ctrl+C after it starts
   or let the headless flow fail — the proxy stays running until the workflow ends).

2. Note the proxy address from the output:
   ```
   Capture proxy listening on http://127.0.0.1:54321
   ```

3. Install the CA cert in your browser (see above).

4. Configure your browser's proxy settings:
   - **HTTP proxy:** `127.0.0.1`
   - **Port:** the printed port (e.g., `54321`)
   - **Also use for HTTPS:** ✓

5. Navigate to the login page and complete the workflow manually.

> **Coming soon:** a `--manual` flag that skips the headless flow and keeps the proxy
> alive until you press Enter.

---

## Captured output format

Each run produces a JSON file at `captures/dothound-workflow-<timestamp>.json`:

```json
{
  "schema": "dothound.workflow_graph.v1",
  "generated_by": "Dothound/0.1.0",
  "started_at_unix_ms": 1732765123456,
  "completed_at_unix_ms": 1732765127890,
  "start_url": "https://example.com/login",
  "redaction": {
    "mode": "sensitive-values-redacted",
    "sensitive_values_included": false
  },
  "summary": {
    "total_exchanges": 7,
    "http_exchanges": 6,
    "https_tunnels": 1
  },
  "nodes": [
    { "id": "node-0001", "kind": "https_tunnel", "label": "CONNECT example.com:443", "exchange_id": "exchange-0001" },
    { "id": "node-0002", "kind": "http", "label": "GET /login", "exchange_id": "exchange-0002" },
    { "id": "node-0003", "kind": "http", "label": "POST /session", "exchange_id": "exchange-0003" }
  ],
  "edges": [
    { "from": "node-0001", "to": "node-0002", "kind": "sequence" },
    { "from": "node-0002", "to": "node-0003", "kind": "sequence" }
  ],
  "exchanges": [
    {
      "id": "exchange-0003",
      "kind": "http",
      "started_at_unix_ms": 1732765124000,
      "finished_at_unix_ms": 1732765125000,
      "client_addr": "127.0.0.1:54321",
      "request": {
        "method": "POST",
        "target": "https://example.com/session",
        "version": "HTTP/1.1",
        "headers": [
          { "name": "Content-Type", "value": "application/x-www-form-urlencoded", "sensitive": false, "value_sha256": null },
          { "name": "Cookie", "value": "<redacted>", "sensitive": true, "value_sha256": "a1b2c3d4..." }
        ],
        "body": {
          "content_type": "application/x-www-form-urlencoded",
          "bytes_seen": 87,
          "bytes_captured": 87,
          "truncated": false,
          "text": "csrf_token=8f3a9b2c&username=alice&password=<redacted>",
          "sensitive": true
        }
      },
      "response": {
        "status_code": 302,
        "reason": "Found",
        "version": "HTTP/1.1",
        "headers": [
          { "name": "Set-Cookie", "value": "<redacted>", "sensitive": true, "value_sha256": "e5f6a7b8..." },
          { "name": "Location", "value": "/dashboard", "sensitive": false, "value_sha256": null }
        ],
        "body": null
      },
      "notes": ["Decrypted HTTPS exchange captured via MITM."]
    }
  ]
}
```

### Key fields

| Field | Description |
|-------|-------------|
| `nodes` | Ordered steps in the workflow — each is one HTTP exchange or tunnel setup |
| `edges` | Sequential connections between nodes (future: branching for parallel requests) |
| `exchanges` | The actual HTTP traffic: request method/URL/headers/body + response status/headers/body |
| `redaction.mode` | `sensitive-values-redacted` (default) or `raw-sensitive-values` |
| `headers[].sensitive` | `true` if the header name matches known sensitive patterns (Authorization, Cookie, etc.) |
| `headers[].value_sha256` | SHA-256 of the redacted value — lets you correlate tokens across exchanges without seeing them |
| `body.text` | String preview of the body (JSON/forms are partially redacted; binary bodies are omitted) |

---

## Project structure

```
DotHound/
├── .dothound/
│   └── ca/
│       ├── dothound-ca.crt   # CA certificate (install this in external tools)
│       └── dothound-ca.key   # CA private key (keep secret)
├── captures/
│   └── dothound-workflow-*.json
├── src/
│   ├── main.rs               # Entry point
│   ├── cli.rs                # CLI prompts & login workflow orchestrator
│   ├── proxy.rs              # HTTP/S proxy with MITM TLS interception
│   ├── ca.rs                 # Certificate authority (generate, sign host certs)
│   ├── auth_engine.rs        # Headless reqwest client (CSRF extraction, form submission)
│   ├── capture.rs            # Data model, JSON serialization, secret redaction
│   ├── types.rs              # Login endpoint validation
│   └── error.rs              # Shared error type alias
├── Cargo.toml
└── README.md
```

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **P1** | ✅ Done | Remove browser dependency; add headless `reqwest` client |
| **P2** | ✅ Done | HTTPS MITM via dynamic per-host certificate generation |
| **P3** | 📋 Planned | State-aware extraction — cookie jar diffing, CSRF chain tracking, OAuth flow detection |
| **P4** | 📋 Planned | Replay engine — replay a captured workflow and diff the results |
| **P5** | 📋 Planned | Export to HAR, cURL commands, Python `requests` scripts, Postman collections |
| — | 📋 Planned | Stable CA across runs (persist and reload the same CA identity) |
| — | 📋 Planned | `--manual` mode for browser-assisted capture with Enter-to-stop |

---

## Limitations

- **CA regenerated each run** — external tools need re-installation of the CA cert
  (built-in headless client is unaffected).
- **HTTP/1.1 only** — HTTP/2 and HTTP/3 are not yet supported; the proxy forces
  `Connection: close` on upstream connections.
- **Chunked transfer encoding** — chunked bodies are buffered in full (up to 10 MB).
- **No WebSocket capture** — WebSocket upgrade requests pass through but the frames
  are not recorded.
- **Single-session** — one login workflow per invocation; no persistent cookie jar
  across runs.

---

## License

MIT (or your preferred license)
