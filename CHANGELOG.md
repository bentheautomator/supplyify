# Changelog

All notable changes to supplyify will be documented in this file.

## [0.2.3] - 2026-04-01

### Fixed
- **`sweep .` bug** — sweep with relative path `.` was silently finding 0 projects because WalkDir's `filter_entry` rejected the root `.` directory as a hidden path. Now canonicalizes the path before walking.
- **OSV API timeout** — added 30-second timeout to prevent indefinite hangs when OSV.dev is unreachable. Previously could hang forever.
- **HTTP client per batch** — replaced per-request client creation with a static `OnceLock` singleton. Eliminates 100-500ms of DNS + TLS overhead per scan.

## [0.2.2] - 2026-04-01

### Fixed
- OSV timeout and HTTP client singleton (initial fix, superseded by 0.2.3)

## [0.2.1] - 2026-04-01

### Fixed
- Removed all references to private/unreleased tools from public README
- `--check-update` now points to GitHub releases instead of private registry
- Added pre-commit hook enforcing version bump on feat/fix commits

## [0.2.0] - 2026-04-01

### Added
- **OSV.dev integration** — queries Google's vulnerability database (80,000+ advisories) via batch API on every scan
- **Advisory links** — every finding now includes a clickable URL to OSV.dev, GitHub Advisory, or original reference
- **Remediation guidance** — actionable text per finding (remove for malware, upgrade to fixed version for vulns)
- **CVE links** — direct links to NVD for findings with CVE identifiers
- **Plugin architecture** — `Plugin` trait with 5 capabilities (IndicatorSource, PolicyEngine, OutputFormat, PostScan, PreScan) for enterprise extensions
- **`--check-update` flag** — checks GitHub releases for newer versions
- **`--no-osv` flag** — fully offline mode, skips OSV.dev lookup

### Changed
- Update command now shows each new indicator individually with severity, name, and references
- Update command tells users OSV.dev still works even if curated feed is unreachable

## [0.1.0] - 2026-03-31

### Added
- Initial release
- Three-layer detection: bundled indicators, OSV.dev live query, offline heuristics
- Ecosystem parsers: npm (package-lock.json, yarn.lock, pnpm-lock.yaml), Cargo (Cargo.lock), pip (requirements.txt, poetry.lock, Pipfile.lock)
- Heuristics: postinstall script detection, version anomaly detection
- Output formats: text (colored terminal), JSON, agent (pipe-delimited for LLMs)
- Sweep mode: parallel multi-project scanning via rayon
- Bundled indicators for axios March 2026 compromise (MAL-2026-2307)
- 13 unit tests
