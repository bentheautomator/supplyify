# Roadmap

## v0.1.0 (Current)

- [x] 3-layer detection (indicators, OSV.dev, heuristics)
- [x] npm, Cargo, pip ecosystem parsers
- [x] Postinstall script analysis and version anomaly detection
- [x] OSV.dev batch API integration (80K+ advisories)
- [x] Sweep mode with parallel scanning
- [x] Output formats: text, JSON, agent
- [x] Bundled indicator database (axios March 2026 compromise)
- [x] `--check-update` self-update check
- [x] `--no-osv` offline mode

## v0.2.0 (Next)

- [ ] **OSV import source** — `supplyify update --source osv` to import from OSV.dev, GitHub Advisory Database, and OpenSSF malicious packages feed directly
- [ ] **STIX/TAXII support** — import/export STIX bundles for interoperability with MISP, OpenCTI, AlienVault OTX
- [ ] **SARIF output** — GitHub Security tab integration (`-f sarif`)
- [ ] **Go ecosystem** — go.sum parser
- [ ] **Composer ecosystem** — composer.lock parser
- [ ] **Obfuscation heuristic** — detect eval(), base64 strings, hex-encoded payloads in flagged packages
- [ ] **Dependency injection heuristic** — diff lockfile against git history, flag new transitive deps

## v0.3.0

- [ ] **Watch mode** — monitor lockfile changes in real-time, alert on new threats
- [ ] **SBOM generation** — CycloneDX and SPDX output from scan results
- [ ] **Bundler ecosystem** — Gemfile.lock parser
- [ ] **NuGet ecosystem** — packages.lock.json parser
- [ ] **Policy engine** — configurable rules (ignore specific packages, enforce minimum severity)
- [ ] **Caching** — cache OSV responses to reduce API calls in sweep mode

## v1.0.0

- [ ] **Stable API** — public Rust library API with semver guarantees
- [ ] **crates.io** — publish to Rust package registry
- [ ] **GitHub Action** — official `bentheautomator/supplyify-action` for zero-config CI
- [ ] **Plugin system** — custom detection modules
- [ ] **Signed indicators** — cryptographic verification of indicator database updates

## Enterprise

See [docs/ENTERPRISE.md](docs/ENTERPRISE.md) for the enterprise offering.

## Contributing

Want to work on something from this roadmap? Open an issue to discuss before starting. See [CONTRIBUTING.md](CONTRIBUTING.md).
