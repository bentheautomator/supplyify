# supplyify Enterprise

## Overview

supplyify is free and open source for individual developers and teams. The Enterprise offering provides additional capabilities for organizations that need centralized visibility, compliance reporting, and priority indicator feeds.

## Community Edition (Free, Open Source)

Everything in the public repo:

- 3-layer detection (indicators, OSV.dev, heuristics)
- npm, Cargo, pip ecosystem support
- Sweep mode for multi-project scanning
- JSON, text, and agent output formats
- Bundled indicator database
- OSV.dev integration (80K+ advisories)
- CLI for local and CI/CD use
- MIT licensed, no restrictions

## Enterprise Edition

For organizations managing supply chain security at scale.

### Centralized Dashboard

- **Fleet visibility** — single pane of glass across all repositories
- **Trend analysis** — track vulnerability counts over time
- **Team views** — filter by team, project, ecosystem
- **Alert routing** — Slack, PagerDuty, email notifications on new threats

### Priority Indicator Feed

- **Early access** — indicators published before public disclosure when responsible disclosure allows
- **Curated intelligence** — verified, high-confidence indicators with full analysis
- **Private indicators** — add organization-specific indicators (internal packages, forked dependencies)
- **Faster updates** — priority feed updates within hours of disclosure, not days

### Compliance & Reporting

- **SARIF output** — GitHub Advanced Security integration
- **SBOM generation** — CycloneDX and SPDX formats
- **Audit logs** — who scanned what, when, with what results
- **Policy engine** — enforce organizational rules (minimum severity, required ecosystems, blocking vs warning)
- **Scheduled reports** — weekly/monthly supply chain health reports per team

### Infrastructure

- **Self-hosted option** — run the indicator feed and dashboard on your own infrastructure
- **Air-gapped mode** — full functionality without internet access using synced indicator bundles
- **SSO integration** — SAML/OIDC for team management
- **API access** — REST API for custom integrations and automation

### Support

- **Priority support** — direct access to maintainers
- **Custom integrations** — help integrating supplyify into your specific CI/CD pipeline
- **Incident response** — assistance when a supply chain attack affects your organization
- **Training** — team training on supply chain security best practices

## Pricing

| Plan | Price | For |
|------|-------|-----|
| **Community** | Free | Individual developers, open source projects |
| **Team** | Contact us | Teams up to 50, centralized dashboard, priority feed |
| **Enterprise** | Contact us | Unlimited, self-hosted, compliance, SLA |

## Contact

Interested in Enterprise? Reach out:

- **Email:** enterprise@supplyify.manualnomore.site
- **Website:** [supplyify.manualnomore.site](https://supplyify.manualnomore.site)

## FAQ

**Is the Community Edition limited in any way?**
No. The CLI, all detection layers, OSV.dev integration, and the bundled indicator database are fully functional in the free version. Enterprise adds centralized management, priority feeds, and compliance features.

**Can I use the Community Edition in my company?**
Yes. MIT license, no restrictions. Use it in CI/CD, on developer machines, in production environments.

**Do I need Enterprise for CI/CD integration?**
No. The Community Edition works perfectly in CI/CD pipelines. Enterprise adds centralized reporting across all your pipelines.

**What if I just need the priority indicator feed?**
Contact us about the Team plan. The priority feed is available independently from the full Enterprise package.
