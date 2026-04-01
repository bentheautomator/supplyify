# supplyify

Fast supply chain attack detection for npm, Cargo, and pip projects.

Scans your lockfiles against known malicious packages, queries the [OSV.dev](https://osv.dev) vulnerability database, and runs offline heuristics — all in milliseconds.

```
supplyify scan .

supplyify — scanning /path/to/project

CRITICAL   axios@1.14.1 — Account takeover, drops RAT via plain-crypto-js postinstall
  ├─ C2: sfrclak.com:8000, 142.11.206.73
  ├─ Ref: https://socket.dev/blog/axios-npm-package-compromised
  └─ Tags: rat, postinstall, account-takeover

──────────────────────────────────
Scanned: /path/to/project (npm) | 847 deps | 3ms
Results: 1 critical, 0 high, 0 medium, 0 low
```

## Install

```bash
# From GitHub releases
curl -fsSL https://github.com/bentheautomator/supplyify/releases/latest/download/supplyify-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/') \
  -o /usr/local/bin/supplyify && chmod +x /usr/local/bin/supplyify

# From source
cargo install --git https://github.com/bentheautomator/supplyify
```

## Usage

### Scan a project

```bash
supplyify scan .                    # Scan current directory
supplyify scan /path/to/project     # Scan specific project
supplyify scan . --no-osv           # Offline only (no network calls)
supplyify scan . --no-heuristics    # Indicators + OSV only, skip heuristics
```

### Sweep all projects

```bash
supplyify sweep ~/projects          # Scan every project under a directory
supplyify sweep ~/git --parallel 8  # Parallel scanning
```

### Quick lookup

```bash
supplyify check axios@1.14.1        # Is this version known-bad?
supplyify check npm:lodash@4.17.21  # Specify ecosystem explicitly
```

### Indicator database

```bash
supplyify indicators                # Show database stats
supplyify update                    # Pull latest indicators
```

### Output formats

```bash
supplyify scan . -f json            # Structured JSON
supplyify scan . -f agent           # Pipe-delimited for LLM consumption
supplyify scan . -o report.json     # Write to file
```

## Detection Layers

| Layer | What | Speed | Network |
|-------|------|-------|---------|
| **1a: Indicators** | Known malicious versions, packages, C2 infrastructure | ~3ms | No |
| **1b: OSV.dev** | Google's open vulnerability database (80K+ advisories) | ~500ms | Yes |
| **2: Heuristics** | Postinstall script analysis, version anomalies | ~100ms | No |

Use `--no-osv` for fully offline scanning (Layer 1a + Layer 2 only).

## Ecosystems

| Ecosystem | Lockfiles | Status |
|-----------|-----------|--------|
| **npm** | package-lock.json, yarn.lock, pnpm-lock.yaml | Supported |
| **Cargo** | Cargo.lock | Supported |
| **pip** | requirements.txt, poetry.lock, Pipfile.lock | Supported |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings |
| 1 | Critical or high severity findings |
| 2 | Medium or low findings only |
| 3 | Scan error |

Use in CI to fail builds on supply chain threats:
```bash
supplyify scan . || exit 1
```

## Indicators

supplyify ships with bundled indicators for known attacks (like the March 2026 axios compromise). Additional indicators come from:

- **OSV.dev** — 80,000+ open source vulnerability advisories, queried live
- **Custom TOML feed** — `supplyify update` pulls curated zero-day indicators

### Adding custom indicators

Create `~/.config/supplyify/indicators.toml`:

```toml
[meta]
version = "2026-04-01"
sources = ["custom"]

[[malicious_version]]
ecosystem = "npm"
package = "suspicious-pkg"
version = "1.0.0"
severity = "critical"
description = "Known malicious package"
date = "2026-04-01"
```

## Motivated by

The [axios npm package compromise](https://socket.dev/blog/axios-npm-package-compromised) (March 2026), where malicious versions 1.14.1 and 0.30.4 were published via account takeover, silently installing a RAT through a `plain-crypto-js` postinstall script.

supplyify was built to detect this class of attack in seconds, offline, across all your projects at once.

## License

MIT
