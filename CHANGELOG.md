# Changelog

All notable changes to supplyify will be documented in this file.

## [0.3.0] - 2026-06-10

A correctness + experimental-detection release. The headline theme: the
scanner no longer **fails open**. Degraded coverage is now surfaced and,
under `--strict`, fails the build instead of reporting a false "clean".

### Fixed (false negatives — these let real threats through)
- **CVSS severity was never parsed** — `parse_cvss_score` split the CVSS
  *vector string* on `/` and tried to parse the trailing metric (`A:H`)
  as a number, which always failed. Every OSV vuln without a
  `database_specific.severity` fell to the Medium default, so 9.8 CVEs
  exited 2 (warn) instead of 1 (fail CI). Now parses CVSS v3/v4 vectors
  via the `cvss` crate. Regression tests added (the OSV module had none).
- **pnpm peer-dep suffixes polluted versions** — keys like
  `/axios@1.7.2(react@18)` parsed to a bogus version that never
  exact-matched an indicator. Suffix is now stripped before the version
  split; pnpm v9 no-leading-slash keys handled too.
- **Yarn Berry (v2+) lockfiles parsed to zero deps** — classic-format
  parser silently dropped the whole npm ecosystem. Berry YAML is now
  detected and parsed.
- **npm aliased installs** (`alias@npm:real-pkg`) are now matched against
  the real package name, not the alias.
- **Suspicious-range matching was semver-only** — pip/Go versions never
  matched, and a malformed range silently matched *every* version. New
  `versioncmp` module does ecosystem-tolerant comparison; malformed
  ranges are surfaced as load-time warnings and match nothing.
- **Broken dedup** — `Vec::dedup_by` only removed adjacent dupes and
  `mem::discriminant` collapsed distinct heuristic kinds. Now dedups on a
  full key, keeping the highest-severity copy.

### Added — fail-closed plumbing
- `ScanResult` now carries `warnings` + `degraded`. Surfaced in all output
  formats (`DEGRADED|true` / `WARNING|...` in agent, `⚠` block in text).
- `--strict` — degraded scans (OSV unreachable, unparseable lockfile, bad
  indicator DB) exit 3 instead of passing as clean.
- `--fail-on <severity>` — configurable CI gate threshold.
- `check` now exits 1 on a hit, queries OSV by default, and consults
  suspicious ranges — making it usable as a pre-install gate primitive.

### Added — experimental detection
- **Dependency-injection heuristic** — diffs each lockfile against git
  HEAD and flags newly-injected transitive deps and version downgrades
  (the actual shape of the March 2026 axios compromise).
- **Obfuscation heuristic** — targeted deep scan of *already-flagged*
  packages for base64 blobs, hex-escape runs, charcode assembly, and
  eval-of-decoded-data.
- **C2 cross-referencing** — indicator-DB C2 addresses are now matched
  against lifecycle scripts and flagged package source (was stored but
  never used). A hit is Critical.
- **Layer 3: codemap integration** — `--no-codemap` now does something:
  runs `codemap security` on flagged packages' installed source.
- **Go ecosystem** — `go.sum` parser.
- **SARIF output** (`-f sarif`) — GitHub Code Scanning ingest.
- **`.supplyify.toml` policy file** — scoped ignore rules with optional
  expiry, so one noisy finding doesn't push teams to `|| true`.
- **Indicator tombstones + checksum-verified feed** — retract published
  indicators via `[[revoked]]`; `update` verifies the feed sha256.

### Changed
- Library/CLI split: `ScanOptions` (detection) is separate from `Config`
  (presentation); the scanner returns data instead of printing/exiting.
- Output format is a typed enum — `-f yaml` is now a CLI error, not a
  silent fall-through to text.
- Agent output gained a versioned `SUPPLYIFY|<ver>|<fmt>` header — this is
  now a parsing contract for gitguard/codemap.
- `report` subcommand removed (it was a byte-for-byte alias of `scan`).
- Plugin registry is now actually invoked by the scanner.

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
