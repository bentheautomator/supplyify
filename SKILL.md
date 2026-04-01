---
name: supply-chain-scan
description: Scan project dependencies for supply chain attacks using supplyify
---

# Supply Chain Scan

Run supplyify to detect malicious packages, compromised versions, and known vulnerabilities in project dependencies.

## When to Use

- Before committing dependency changes (lockfile updates)
- At the start of a session in an unfamiliar project
- After running `npm install`, `cargo update`, `pip install`, or any dependency change
- When a supply chain advisory is published

## Steps

1. Check if supplyify is installed:
   ```bash
   command -v supplyify || echo "Install: cargo install --git https://github.com/bentheautomator/supplyify"
   ```

2. Scan the current project:
   ```bash
   supplyify scan . -f agent
   ```

3. If findings are critical or high:
   - Stop work immediately
   - Report the finding to the user via AskUserQuestion
   - Do NOT proceed with builds, deploys, or commits until the user acknowledges

4. If findings are medium or low:
   - Note them but continue working
   - Mention in your next status update

5. For a broader check across all local projects:
   ```bash
   supplyify sweep ~/projects -f agent --parallel 8
   ```

## Flags

- `--no-osv` — fully offline, skip OSV.dev lookup (faster, but fewer indicators)
- `-f agent` — pipe-delimited output optimized for LLM parsing
- `-f json` — structured JSON for programmatic use

## Exit Codes

- `0` = clean
- `1` = critical/high findings — STOP and alert user
- `2` = medium/low findings — note and continue
