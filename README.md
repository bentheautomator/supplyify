# supplyify

Fast, offline-first supply chain attack detection for npm, Cargo, and pip projects.

Scans your lockfiles against known malicious packages, queries [OSV.dev](https://osv.dev) (80,000+ advisories), and runs offline heuristics — **all in milliseconds.**

```
$ supplyify scan .

CRITICAL   axios@1.14.1 — Account takeover, drops RAT via plain-crypto-js postinstall
  ├─ C2: sfrclak.com:8000, 142.11.206.73
  ├─ Ref: https://socket.dev/blog/axios-npm-package-compromised
  └─ Tags: rat, postinstall, account-takeover

CRITICAL   axios@1.14.1 — [MAL-2026-2307] Malicious axios version (via OSV.dev)
  └─ Tags: osv, malware

Scanned: ./my-project (npm) | 847 deps | 3ms
Results: 2 critical, 0 high, 0 medium, 0 low
```

## The Problem

On March 27, 2026, the [axios npm package was compromised](https://socket.dev/blog/axios-npm-package-compromised). An attacker gained access to a maintainer's account and published malicious versions `1.14.1` and `0.30.4`. These versions silently installed `plain-crypto-js` via a postinstall script — a remote access trojan that phoned home to `sfrclak.com:8000`, giving the attacker control of every machine that ran `npm install`.

axios has **50 million weekly downloads**. The malicious versions were live for hours before anyone noticed.

When this happened, most developers had the same question: **am I affected?** The answer required manually checking lockfiles across every project, one at a time. 50 projects means 50 manual checks. If you're a team lead, multiply by every developer on the team.

Existing tools didn't help. SaaS scanners require uploading your lockfiles to a third party. GitHub's Dependabot only covers repos hosted on GitHub. `npm audit` only checks one project at a time and misses malicious packages that aren't in the npm advisory database yet.

## How supplyify Solves This

**One command. Every project. Milliseconds.**

```bash
$ supplyify sweep ~/projects --parallel 8

Sweeping ~/projects ... found 194 projects

  my-app          CRITICAL  axios@1.14.1 (RAT dropper)
  dashboard       CLEAN     214 deps
  api-server      CLEAN     89 deps
  ...

Summary: 194 projects | 82,780 total deps | 1 critical | 518ms
```

supplyify works in three layers:

1. **Bundled indicators** (~3ms, offline) — known malicious packages compiled into the binary. Zero network calls. Catches known threats instantly.
2. **OSV.dev** (~500ms, online) — queries Google's open vulnerability database covering 80,000+ advisories across every major ecosystem. Catches everything that's been publicly disclosed.
3. **Heuristics** (~100ms, offline) — detects suspicious postinstall scripts and version anomalies. Catches threats *before* advisories are published.

No account. No lockfiles uploaded to third parties. No SaaS dashboard. Just a binary that tells you the truth in milliseconds.

## Keeping Indicators Current

New supply chain attacks happen constantly. Staying current is one command:

```bash
$ supplyify update

supplyify Checking for indicator updates...

  New indicators:
    CRITICAL evil-pkg@2.0.1 — Backdoor installed via postinstall
      Ref: https://socket.dev/blog/evil-pkg-analysis
    CRITICAL typo-lodash@4.17.22 — Typosquat exfiltrating env vars

  ✓ 2 new indicators added (total: 47)
  ✓ Saved to ~/.config/supplyify/indicators.toml
```

Three indicator sources work together:
- **Bundled indicators** ship with every release — always available, zero setup
- **`supplyify update`** pulls the latest curated zero-day indicators from the [supplyify-indicators](https://github.com/bentheautomator/supplyify-indicators) community feed
- **OSV.dev** is queried live on every scan — 80,000+ advisories updated continuously by Google, GitHub, and the open source community

Even if you never run `supplyify update`, the live OSV.dev layer catches everything in public advisory databases. The bundled and community indicators add zero-day coverage for threats that haven't hit public feeds yet.

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

## About the Author

Built by [Ben "The Automator" Christensen](https://www.linkedin.com/in/ben-the-automator-c/) (CPDE, CCP) — a cybersecurity and automation executive with 20+ years in the field. Ben is the founder of [Automator Solutions](https://automatorsolutions.com), an advisory board member at [Revelstoke Security](https://www.linkedin.com/posts/krusebob_two-leading-mdr-pros-join-revelstokes-new-activity-6980929558707412992-eG0X), and the published author of *Demystifying Automation: A Non-Technical Guide to Streamlining Your Business*.

His career spans security orchestration (SOAR), incident response automation, and building AI-powered tooling that eliminates manual work at scale — with a track record of $15M+ saved and 500,000+ hours automated across organizations. He builds and maintains a suite of open source security and developer tools including [codemap](https://github.com/bentheautomator/codemap) (code intelligence), [agentdb](https://github.com/bentheautomator/agentdb) (operational tracking), and the [AI Toolkit](https://github.com/bentheautomator/ai-toolkit) (30+ local-first AI tools).

supplyify exists because when the axios compromise hit in March 2026, the answer to "am I affected?" shouldn't require uploading lockfiles to a SaaS vendor or checking projects one at a time. It should be one command, instant, and run entirely on your machine.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add indicators, parsers, and heuristics.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT
