# supplyify — Claude Code Integration

## Quick Start

Scan the current project for supply chain threats:

```bash
supplyify scan .
```

Scan all projects in a directory:

```bash
supplyify sweep ~/projects --parallel 8
```

## When to Use

- **Before installing dependencies** — scan lockfiles after `npm install`, `cargo update`, or `pip install`
- **In CI pipelines** — add `supplyify scan . || exit 1` to fail builds on threats
- **After security advisories** — run `supplyify sweep ~/projects` to check all projects
- **Routine audits** — sweep your entire development directory periodically

## Commands

| Command | Purpose |
|---------|---------|
| `supplyify scan <path>` | Scan a single project (all detection layers) |
| `supplyify sweep <dir>` | Find and scan all projects under a directory |
| `supplyify check <pkg@ver>` | Quick lookup — is this version known-bad? |
| `supplyify indicators` | Show indicator database stats |
| `supplyify update` | Pull latest indicators from remote feed |

## Flags

| Flag | Effect |
|------|--------|
| `--no-osv` | Skip OSV.dev online lookup (fully offline) |
| `--no-heuristics` | Skip Layer 2 heuristics |
| `--no-codemap` | Skip Layer 3 codemap deep analysis of flagged packages |
| `--strict` | Fail closed — a degraded scan (OSV unreachable, unparseable lockfile) exits 3 instead of passing as clean |
| `--fail-on <sev>` | Minimum severity that exits 1 (`low`/`medium`/`high`/`critical`, default `high`) |
| `-f json` | JSON output |
| `-f agent` | Pipe-delimited output for LLM consumption |
| `-f sarif` | SARIF 2.1.0 for GitHub Code Scanning |
| `--check-update` | Check for newer supplyify version |

## Exit Codes

- `0` — clean
- `1` — findings at or above `--fail-on` (default: critical/high) — fail CI
- `2` — findings below `--fail-on` only — warn
- `3` — `--strict` and the scan was degraded (coverage reduced; "couldn't check" ≠ "clean")

## Suppressing findings (`.supplyify.toml`)

Drop a `.supplyify.toml` in the project root to ignore known-acceptable findings
instead of resorting to `|| true`:

```toml
[[ignore]]
package = "legacy-internal"
version = "0.0.0-build"   # optional — any version if omitted
kind = "version_anomaly"  # optional — any kind if omitted
reason = "internal build tag, not a registry package"
expires = "2026-12-31"    # optional — rule stops applying after this date
```

Suppressed findings are counted (`IGNORED|N` in agent output) but never fail the scan.

## Example: Agent Integration

```bash
# Before starting work on a project, scan it
supplyify scan . -f agent --no-osv

# Output:
# CMD|scan
# PROJECT|.
# ECOSYSTEM|npm
# DEPS|847
# ---
# SUMMARY|0 critical, 0 high, 0 medium, 0 low | 3ms
```

## Detection Layers

1. **Indicators** (offline, ~3ms) — bundled known-bad packages, versions, C2 infrastructure; C2 addresses are cross-referenced against installed package source and lifecycle scripts
2. **OSV.dev** (online, ~500ms) — Google's vulnerability database with 80K+ advisories
3. **Heuristics** (offline, ~100ms) — postinstall script analysis, version anomalies, and **dependency-injection detection** (lockfile diff vs git HEAD: new transitive deps + downgrades)
4. **Targeted deep scan** (offline) — for packages flagged High+ by earlier layers only: obfuscation markers (base64/hex/charcode/eval-of-decoded), and `codemap security` if the binary is installed

## Output format contract (agent mode)

`-f agent` emits a versioned header — `SUPPLYIFY|<tool-version>|<format-version>` —
followed by `FINDING|`, `C2|`, `WARNING|`, `DEGRADED|true`, `IGNORED|N`, and
`SUMMARY|` lines. The format version is bumped only on incompatible grammar
changes, so downstream parsers (gitguard, codemap) can rely on it.
