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
| `--no-codemap` | Skip Layer 3 codemap analysis |
| `-f json` | JSON output |
| `-f agent` | Pipe-delimited output for LLM consumption |
| `--check-update` | Check for newer supplyify version |

## Exit Codes

- `0` — clean
- `1` — critical or high findings (fail CI)
- `2` — medium or low findings only (warn)

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

1. **Indicators** (offline, ~3ms) — bundled known-bad packages, versions, C2 infrastructure
2. **OSV.dev** (online, ~500ms) — Google's vulnerability database with 80K+ advisories
3. **Heuristics** (offline, ~100ms) — postinstall script analysis, version anomalies
