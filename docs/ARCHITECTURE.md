# Architecture

## Overview

supplyify is a three-layer detection system that scans package lockfiles for supply chain threats.

```
                    supplyify scan .
                         │
                         ▼
              ┌─────────────────────┐
              │  Project Discovery  │  Detect ecosystems, parse lockfiles
              │  ecosystems/mod.rs  │  → Vec<(Ecosystem, Vec<Dependency>)>
              └─────────┬───────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
     ┌─────────┐  ┌──────────┐  ┌──────────┐
     │ Layer 1a│  │ Layer 1b │  │ Layer 2  │
     │Indicator│  │ OSV.dev  │  │Heuristics│
     │ Match   │  │ API      │  │          │
     │  ~3ms   │  │ ~500ms   │  │ ~100ms   │
     │ offline │  │ online   │  │ offline  │
     └────┬────┘  └────┬─────┘  └────┬─────┘
          │            │             │
          └─────────────┼─────────────┘
                        ▼
              ┌─────────────────────┐
              │   Finding Merge     │  Dedup, sort by severity
              │   scanner.rs        │  → ScanResult
              └─────────┬───────────┘
                        ▼
              ┌─────────────────────┐
              │   Output Format     │  text / json / agent
              │   output/mod.rs     │
              └─────────────────────┘
```

## Detection Layers

### Layer 1a: Indicator Matching (offline, ~3ms)

**File:** `src/indicators/mod.rs`

Matches dependencies against a bundled database of known threats:
- **Malicious versions** — specific package@version pairs (e.g., axios@1.14.1)
- **Malicious packages** — entire packages that are malicious at any version (e.g., plain-crypto-js)
- **C2 indicators** — known command-and-control infrastructure
- **Suspicious ranges** — version ranges published during known compromise windows

The database is compiled into the binary via `include_str!("bundled.toml")` and can be extended with user config at `~/.config/supplyify/indicators.toml`.

Uses `HashMap` indexes for O(1) lookups per dependency.

### Layer 1b: OSV.dev (online, ~500ms)

**File:** `src/osv.rs`

Queries the [OSV.dev batch API](https://osv.dev) with all discovered dependencies in a single request. Returns advisories from:
- GitHub Advisory Database
- OpenSSF Malicious Packages (MAL- prefixed IDs)
- PyPI, crates.io, npm advisories
- NVD/CVE cross-references

Disabled with `--no-osv` for fully offline operation.

### Layer 2: Heuristics (offline, ~100ms)

**File:** `src/heuristics/`

Pattern-based detection that doesn't require a database:
- **Postinstall scripts** — scans `node_modules/*/package.json` for suspicious lifecycle scripts (curl, wget, eval, base64, network calls)
- **Version anomalies** — flags non-semver version strings

Disabled with `--no-heuristics`.

## Module Structure

```
src/
├── main.rs              CLI entry point (clap 4 derive)
├── lib.rs               Core types: Config, Severity, Ecosystem, Finding, ScanResult
├── scanner.rs           Orchestrates all 3 layers, produces ScanResult
├── sweep.rs             Multi-project discovery + parallel scanning (rayon)
├── osv.rs               OSV.dev batch API client
├── indicators/
│   ├── mod.rs           IndicatorDb: load, merge, check, index
│   └── bundled.toml     Compiled-in indicator database
├── ecosystems/
│   ├── mod.rs           EcosystemParser trait, discover_project()
│   ├── npm.rs           package-lock.json, yarn.lock, pnpm-lock.yaml
│   ├── cargo.rs         Cargo.lock
│   └── pip.rs           requirements.txt, poetry.lock, Pipfile.lock
├── heuristics/
│   ├── mod.rs           Heuristic registry
│   ├── postinstall.rs   npm lifecycle script analysis
│   └── version.rs       Version string anomaly detection
├── output/
│   ├── mod.rs           Format dispatcher
│   ├── text.rs          Colored terminal output
│   ├── json.rs          Structured JSON
│   └── agent.rs         Pipe-delimited LLM format
└── commands/
    ├── scan.rs          Single project scan
    ├── sweep.rs         Multi-project sweep
    ├── check.rs         Quick package@version lookup
    ├── indicators.rs    Database stats
    ├── update.rs        Pull remote indicators
    └── check_update.rs  Version update check
```

## Data Flow

1. **Input:** Project path
2. **Discovery:** Walk path for lockfiles, detect ecosystem(s)
3. **Parsing:** Extract `Vec<Dependency>` from each lockfile
4. **Layer 1a:** Hash-match against indicator DB (HashMap lookups)
5. **Layer 1b:** Batch POST to OSV.dev API (all deps in one request)
6. **Layer 2:** Run heuristics on project directory
7. **Merge:** Combine findings, dedup by (package, version, kind), sort by severity
8. **Output:** Format as text/json/agent, write to stdout or file
9. **Exit:** Code 0 (clean), 1 (critical/high), 2 (medium/low)

## Design Decisions

- **No async in scanner** — The core scan loop is synchronous. `reqwest::blocking` for OSV. Simpler code, easier to reason about.
- **rustls over OpenSSL** — Pure Rust TLS enables cross-compilation without system deps.
- **include_str! for indicators** — Zero file I/O for bundled indicators. Binary is self-contained.
- **rayon for sweep** — Parallel project scanning with configurable thread count.
- **HashMap indexes** — Pre-built at scan start for O(1) indicator lookups per dep.
