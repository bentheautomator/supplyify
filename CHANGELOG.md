# Changelog

All notable changes to supplyify will be documented in this file.

## [0.3.0] - 2026-07-23

### Added
- **`--strict` flag** (v0.3.0 scope: **indicator DB degradation only**): when `IndicatorDb::load()` fails at scan start, the whole Layer 1 coverage is zero — under `--strict` this exits `3` instead of silently passing as clean. Closes the integration contract gitguard's pre-push lefthook has been written against since design (bentheautomator/gitguard#293 / CLAUDE.md's supply-chain gate section) — pre-0.3.0 the flag simply errored on parse, blocking every push that used it. **Not yet covered by --strict** (tracked as follow-up): OSV.dev unreachable (needs `osv::query_batch` to bubble network errors instead of silently returning empty findings), lockfile parse errors (needs each ecosystem parser to distinguish "no lockfile" from "found but malformed"). The `strict` boolean is wired end-to-end (Config → ScanResult.exit_code_v3 → CLI exit) so those follow-ups are pure signal-bubbling, no API changes.
- **`--fail-on <severity>` flag**: exit codes gate on findings at or above the given severity (`low`, `medium`, `high`, `critical`; default `high`). Findings BELOW `fail_on` exit `0` — the whole point of the flag is to tell the caller what blocks; anything below that surfaces in the report but shell gates pass. `--fail-on critical` lets High findings surface without blocking. **Behavior change from pre-0.3.0**: the old `exit_code()` returned `2` for any-finding-below-High. That "was anything found at all" signal made shell gates (lefthook, ci) fail on Medium/Low findings that the user explicitly asked to demote via `--fail-on high`. Legacy `exit_code()` now aliases to `exit_code_v3(High, false)` so pre-0.3.0 in-process embeddings see the new (looser) semantics too — a real behavior change, called out here to avoid silent surprise. Callers that need the old "found anything?" signal should count `findings.len()` directly.
- `Severity::FromStr` for CLI parsing.
- `ScanResult::degraded: bool` field (`#[serde(default)]` for backwards compat with any consumers reading older JSON).
- `ScanResult::exit_code_v3(fail_on, strict)` — the strict-aware exit code path. `ScanResult::exit_code()` preserved as a wrapper that calls `exit_code_v3(Severity::High, false)` so pre-0.3.0 embeddings keep the same verdict.

### Integration
- Matches gitguard/lefthook's expected surface: `supplyify scan . --no-osv --strict --fail-on high -f agent` (ship pipeline) and `supplyify scan . --strict --fail-on high -f agent` (pre-push lefthook) now both run instead of errored-on-parse.

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
