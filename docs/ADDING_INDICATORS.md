# Adding Indicators

This guide walks through adding a new malicious package indicator to supplyify's bundled database.

## When to Add an Indicator

Add an indicator when you have **verified evidence** of a malicious package:
- A published security advisory (Socket.dev, Snyk, npm audit)
- An OSV/CVE entry
- A credible blog post with technical analysis
- First-hand analysis of the malicious code

Do **not** add indicators for:
- Packages with known vulnerabilities (those are in OSV.dev already)
- Suspicious but unconfirmed packages (open a discussion first)
- Typosquats that haven't been confirmed malicious

## Step 1: Identify the Indicator Type

| Type | When to Use | Example |
|------|-------------|---------|
| `malicious_version` | Specific version is compromised | axios 1.14.1 |
| `malicious_package` | Entire package is malicious at any version | plain-crypto-js |
| `c2_indicator` | Known command-and-control infrastructure | sfrclak.com:8000 |
| `suspicious_range` | Range of versions published during compromise | axios >=0.30.0,<0.30.5 |

## Step 2: Write the TOML Entry

Edit `src/indicators/bundled.toml`:

### Malicious Version

```toml
[[malicious_version]]
ecosystem = "npm"
package = "compromised-pkg"
version = "2.0.1"
severity = "critical"
description = "Account takeover — installs backdoor via postinstall script"
c2 = ["evil.example.com:443", "203.0.113.50"]
cve = "CVE-2026-XXXXX"
references = ["https://socket.dev/blog/compromised-pkg-analysis"]
date = "2026-04-01"
tags = ["backdoor", "postinstall", "account-takeover"]
```

### Malicious Package

```toml
[[malicious_package]]
ecosystem = "npm"
package = "typosquat-express"
severity = "critical"
description = "Typosquat of express — exfiltrates environment variables on import"
references = ["https://advisory-url.example.com"]
date = "2026-04-01"
tags = ["typosquat", "data-exfiltration"]
```

### C2 Indicator

```toml
[[c2_indicator]]
address = "evil.example.com"
port = 443
ip = "203.0.113.50"
associated_campaigns = ["compromised-pkg-2026-04"]
```

### Suspicious Range

```toml
[[suspicious_range]]
ecosystem = "npm"
package = "compromised-pkg"
range = ">=2.0.0,<2.0.3"
severity = "high"
description = "Published during account takeover window"
```

## Step 3: Test

```bash
# Build
cargo build

# Verify the indicator loads
./target/debug/supplyify indicators
# Should show updated counts

# Test detection
./target/debug/supplyify check compromised-pkg@2.0.1
# Should show: CRITICAL compromised-pkg@2.0.1 ...

# Run full test suite
cargo test
```

## Step 4: Submit PR

```bash
git checkout -b indicator/compromised-pkg
git add src/indicators/bundled.toml
git commit -m "indicator(npm): add compromised-pkg@2.0.1"
git push -u origin indicator/compromised-pkg
```

In the PR description, include:
- Link to the advisory or analysis
- Brief description of the attack
- How you verified the indicator

## Field Reference

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `ecosystem` | Yes | string | `npm`, `cargo`, `pip` |
| `package` | Yes | string | Exact package name (case-sensitive for npm) |
| `version` | Yes* | string | Semver format. *Not required for `malicious_package` |
| `severity` | Yes | string | `critical`, `high`, `medium`, `low` |
| `description` | Yes | string | 1-2 sentences describing the attack |
| `date` | Yes | string | ISO 8601 date (YYYY-MM-DD) |
| `c2` | No | array | C2 addresses as "host:port" strings |
| `cve` | No | string | CVE identifier if assigned |
| `references` | No | array | URLs to advisories, blog posts |
| `tags` | No | array | Attack categories for filtering |
| `range` | Yes* | string | *Only for `suspicious_range`. Format: `>=X.Y.Z,<A.B.C` |

## Severity Guide

| Severity | Criteria |
|----------|----------|
| **critical** | Remote code execution, RAT, data exfiltration, credential theft |
| **high** | Cryptominer, DNS hijacking, significant data collection |
| **medium** | Suspicious behavior without confirmed malicious intent |
| **low** | Anomalous metadata, potential typosquat without payload |
