---
name: New Indicator
about: Report a malicious package or compromised version for the indicator database
title: "indicator: "
labels: indicator
---

## Package Details

- **Ecosystem:** (npm / cargo / pip / go / composer / bundler)
- **Package name:**
- **Affected version(s):**
- **Severity:** (critical / high / medium / low)

## Description

What does this package/version do? How was it compromised?

## Evidence

- **Advisory URL:**
- **CVE (if assigned):**
- **OSV ID (if exists):**
- **Blog post or writeup:**

## Attack Details (if known)

- **Attack vector:** (account takeover / typosquat / dependency confusion / maintainer gone rogue)
- **Payload:** (RAT / cryptominer / data exfiltration / backdoor)
- **C2 infrastructure:** (domains, IPs, ports)
- **Indicators of compromise:**

## TOML Entry (optional)

If you've already formatted the indicator:

```toml
[[malicious_version]]
ecosystem = ""
package = ""
version = ""
severity = ""
description = ""
c2 = []
cve = ""
references = []
date = ""
tags = []
```
