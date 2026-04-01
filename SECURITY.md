# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in supplyify itself (not in a package it detects), please report it responsibly.

**Do not open a public issue.**

Email: **security@manualnomore.site**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 1 week
- **Fix or mitigation:** Based on severity

| Severity | Target Resolution |
|----------|------------------|
| Critical | 24 hours |
| High | 1 week |
| Medium | 2 weeks |
| Low | Next release |

## Scope

In scope:
- Code execution vulnerabilities in supplyify
- Indicator database poisoning vectors
- Authentication bypass in update mechanism
- Dependency confusion in supplyify's own dependencies

Out of scope:
- Vulnerabilities in packages that supplyify *detects* (report those to the affected project)
- Denial of service via large lockfiles (known limitation)
- Issues in third-party dependencies (report upstream, then notify us)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x | Yes |

## Disclosure Policy

We follow coordinated disclosure. After a fix is released, we will:
1. Credit the reporter (unless anonymity is requested)
2. Publish a security advisory on GitHub
3. Update the CHANGELOG

## Indicator Integrity

The bundled indicator database (`src/indicators/bundled.toml`) is the most security-sensitive component. All indicator changes require:
- Verifiable reference (advisory URL, CVE, blog post)
- Review by a maintainer before merge
- No unsigned or unverified indicators
