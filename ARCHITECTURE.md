# Akemi Architecture (v2.0.0-dev)
## Ai generated
## Design Principles

1. **Interface-driven**: Every subsystem implements a well-defined interface in `internal/core/interfaces.go`. This enables loose coupling, easy testing, and future swap-out of implementations.

2. **Service layer**: `internal/service/` contains thin wrappers that adapt the existing modules to the new interfaces. This allows incremental migration without breaking existing code.

3. **Backward compatibility**: All legacy CLI flags continue to work. The new Cobra subcommands (`akemi scan`, `akemi discover`, etc.) are additive.

4. **Context propagation**: Every I/O operation accepts `context.Context` for cancellation, timeouts, and trace ID propagation.

5. **Structured logging**: All logging uses Go's `log/slog` package for structured, leveled output.

---

## Directory Layout

```
cmd/
  Akemi/
    Akemi.go              # Entry point → delegates to commands/
    password.go           # Terminal password reading (unchanged)
    commands/
      root.go             # Root command + legacy flag backward compat
      scan.go             # akemi scan
      discover.go         # akemi discover
      probe.go            # akemi probe
      fuzz.go             # akemi fuzz
      subdomain.go        # akemi subdomain
      report.go           # akemi report
      graph.go            # akemi graph

internal/
  core/
    interfaces.go         # All service interfaces + canonical types
    errors.go             # Structured error types
    context.go            # Trace IDs, logging helpers
    types.go              # Legacy types (preserved)
    paths.go              # Path resolution (preserved)

  service/
    scanner.go            # ScannerService implementing core.Scanner
    discovery.go           # DiscoveryService implementing core.Discoverer
    vuln.go               # VulnService implementing core.Prober
    subdomain.go           # SubdomainService implementing core.SubEnumerator
    reporting.go           # ReportingService implementing core.Reporter

  config/
    config.go             # Unified configuration system (TOML + env + flags)

  app/                    # Legacy facade (preserved for backward compat)
  recon/                  # Reconnaissance modules (preserved)
  vuln/                   # Vulnerability probe engine (preserved)
  exploit/                # ExploitDB matching (preserved)
  reporting/              # Report/graph generators (preserved)
  fuzz/                   # Fuzzing engine (preserved)
  dothound/               # DotHound integration (preserved)
  platform/proxy/         # Proxy handling (preserved)
  cli/ui/                 # ASCII art / banner (preserved)

Akemi-Spear/              # Rust port scanner engine
DotHound/                  # Rust auth workflow capture engine
probes/                    # YAML vulnerability probe templates
config/                    # Runtime configuration files
```

---

## Interface Hierarchy

```
core.Scanner        → service.ScannerService      → recon.PortScanner
core.Discoverer     → service.DiscoveryService     → recon.Crawl, recon.AnalyzeJS, etc.
core.Prober         → service.VulnService          → vuln.ProbeParams, vuln.LoadTemplates
core.SubEnumerator  → service.SubdomainService     → recon.EnumerateSubdomains
core.Reporter       → service.ReportingService     → reporting.ScanReport, reporting.BuildGraph
core.Fuzzer         → (direct)                     → fuzz.RunFuzzer
core.ExploitLookup   → (direct)                     → exploit.ExploitDB
```

---

## Data Flow

```
CLI (Cobra)
  │
  ├─ parse flags → build core.*Config structs
  │
  ├─ getServices() → lazily init service layer
  │
  ├─ call service methods with ctx + config
  │     │
  │     ├─ service validates, enriches context with trace ID
  │     │
  │     ├─ delegates to legacy module (recon/vuln/etc.)
  │     │
  │     └─ converts legacy types → core.* types
  │
  └─ format & display results to stdout
```

## Configuration Resolution Order

1. Default values (`config.DefaultConfig()`)
2. TOML config file (`.akemi.toml`, `~/.akemi/config.toml`)
3. Environment variables (`AKEMI_*`)
4. CLI flags (highest priority)

---

## Migration Notes

### From v1.x to v2.0

- All v1.x flags still work on the root `akemi` command
- New subcommands provide a cleaner, more discoverable interface
- Internal types have been consolidated in `core/interfaces.go`
- Legacy types in `recon/`, `vuln/`, etc. still exist and are converted at the service boundary
- The `internal/app/` facade is preserved but new code should use services directly

### Future Phases

See the Phase 2+ roadmap for:
- MCP server integration (Phase 2)
- AI agent system (Phase 3-4)
- Persistent database (Phase 5)
- Web dashboard (Phase 6)
