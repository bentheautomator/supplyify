# CI/CD Integration Guide

Integrate supplyify into your build pipeline to automatically block compromised dependencies before they reach production.

## Quick Start

Add one line to your CI pipeline:

```bash
supplyify scan . || exit 1
```

That's it. Exit code 1 = critical or high findings = pipeline fails.

## GitHub Actions

### Basic (fail on threats)

```yaml
name: Supply Chain Check
on: [push, pull_request]

jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install supplyify
        run: |
          curl -fsSL https://github.com/bentheautomator/supplyify/releases/latest/download/supplyify-linux-amd64 \
            -o /usr/local/bin/supplyify && chmod +x /usr/local/bin/supplyify

      - name: Scan dependencies
        run: supplyify scan . --no-osv
```

### With OSV.dev (online, more comprehensive)

```yaml
      - name: Scan dependencies (with OSV.dev)
        run: supplyify scan .
```

### JSON output for downstream processing

```yaml
      - name: Scan dependencies
        run: supplyify scan . -f json -o supplyify-report.json || true

      - name: Upload scan report
        uses: actions/upload-artifact@v4
        with:
          name: supplyify-report
          path: supplyify-report.json
```

### Warn but don't fail (medium/low findings)

```yaml
      - name: Scan dependencies
        run: |
          supplyify scan .
          EXIT_CODE=$?
          if [ $EXIT_CODE -eq 1 ]; then
            echo "::error::Critical supply chain threat detected!"
            exit 1
          elif [ $EXIT_CODE -eq 2 ]; then
            echo "::warning::Supply chain warnings found (medium/low severity)"
          fi
```

### Monorepo (sweep all projects)

```yaml
      - name: Sweep all projects
        run: supplyify sweep . --parallel 4
```

## GitLab CI

```yaml
supply-chain-scan:
  stage: test
  image: ubuntu:latest
  before_script:
    - curl -fsSL https://github.com/bentheautomator/supplyify/releases/latest/download/supplyify-linux-amd64
        -o /usr/local/bin/supplyify && chmod +x /usr/local/bin/supplyify
  script:
    - supplyify scan .
  allow_failure: false
```

## Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Supply Chain Check') {
            steps {
                sh '''
                    curl -fsSL https://github.com/bentheautomator/supplyify/releases/latest/download/supplyify-linux-amd64 \
                      -o /tmp/supplyify && chmod +x /tmp/supplyify
                    /tmp/supplyify scan .
                '''
            }
        }
    }
}
```

## Docker

### In a Dockerfile

```dockerfile
# Multi-stage: scan dependencies before building
FROM ubuntu:latest AS security-check
RUN curl -fsSL https://github.com/bentheautomator/supplyify/releases/latest/download/supplyify-linux-amd64 \
  -o /usr/local/bin/supplyify && chmod +x /usr/local/bin/supplyify
COPY package-lock.json .
RUN supplyify scan .

# Only reaches this stage if scan passes
FROM node:20-slim AS build
COPY . .
RUN npm ci && npm run build
```

### As a standalone scanner

```bash
# Scan a project directory from outside
docker run --rm -v $(pwd):/project ubuntu:latest bash -c \
  "curl -fsSL https://github.com/bentheautomator/supplyify/releases/latest/download/supplyify-linux-amd64 \
   -o /usr/local/bin/supplyify && chmod +x /usr/local/bin/supplyify && \
   supplyify scan /project"
```

## Pre-commit Hook

Scan on every commit (catches compromised deps immediately after `npm install`):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: supplyify
        name: Supply Chain Scan
        entry: supplyify scan . --no-osv --quiet
        language: system
        pass_filenames: false
        files: '(package-lock\.json|yarn\.lock|Cargo\.lock|requirements\.txt|poetry\.lock)'
```

Or with lefthook:

```yaml
# lefthook.yml
pre-commit:
  commands:
    supply-chain:
      glob: "{package-lock.json,yarn.lock,Cargo.lock,requirements.txt,poetry.lock}"
      run: supplyify scan . --no-osv --quiet
```

## Team Workflows

### Recommended Pipeline Placement

```
Code Push
  └─ Lint & Format
  └─ Unit Tests
  └─ supplyify scan .     ← HERE (after tests, before deploy)
  └─ Build
  └─ Deploy
```

Run supplyify **after** tests but **before** build/deploy. This ensures:
- Developers get fast feedback on their code first
- Compromised dependencies are caught before artifacts are built
- No wasted build time on projects with known threats

### For Dependency Update PRs

When Dependabot, Renovate, or manual updates change lockfiles, supplyify should run automatically:

```yaml
# Trigger on lockfile changes
on:
  pull_request:
    paths:
      - 'package-lock.json'
      - 'yarn.lock'
      - 'pnpm-lock.yaml'
      - 'Cargo.lock'
      - 'requirements.txt'
      - 'poetry.lock'
      - 'Pipfile.lock'
```

### Scheduled Sweeps

Run a nightly sweep across all your repos to catch newly published advisories:

```yaml
name: Nightly Supply Chain Sweep
on:
  schedule:
    - cron: '0 6 * * *'  # 6 AM UTC daily

jobs:
  sweep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install supplyify
        run: |
          curl -fsSL https://github.com/bentheautomator/supplyify/releases/latest/download/supplyify-linux-amd64 \
            -o /usr/local/bin/supplyify && chmod +x /usr/local/bin/supplyify
      - name: Sweep
        run: supplyify scan . -f json -o report.json
      - name: Alert on findings
        if: failure()
        run: echo "Supply chain threat detected! Check report.json"
        # Add: Slack webhook, email, PagerDuty, etc.
```

## Offline vs Online Mode

| Mode | Flag | What Runs | Use Case |
|------|------|-----------|----------|
| **Full** | (default) | Indicators + OSV + Heuristics | Best coverage, requires internet |
| **Offline** | `--no-osv` | Indicators + Heuristics | Air-gapped environments, fast CI |
| **Indicators only** | `--no-osv --no-heuristics` | Indicators only | Fastest, minimal |

For air-gapped or restricted environments, use `--no-osv`. The bundled indicator database still catches known malicious packages without any network calls.

## Exit Codes Reference

| Code | Meaning | CI Action |
|------|---------|-----------|
| 0 | Clean | Pass |
| 1 | Critical or High findings | **Fail the build** |
| 2 | Medium or Low findings | Warn (configurable) |
| 3 | Scan error | Investigate |
