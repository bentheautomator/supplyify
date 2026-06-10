use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Duration;

use crate::{Dependency, Ecosystem, Finding, FindingDetails, FindingKind, Severity};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const BATCH_SIZE: usize = 1000;
const OSV_TIMEOUT_SECS: u64 = 30;

/// Shared HTTP client with timeout — created once, reused across all batches
fn osv_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(OSV_TIMEOUT_SECS))
            .user_agent("supplyify")
            .build()
            .expect("Failed to build HTTP client")
    })
}

/// Outcome of an OSV lookup. `warnings` non-empty means coverage was
/// reduced — some or all dependencies were NOT checked against OSV.
pub struct OsvOutcome {
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

/// Query OSV.dev for known vulnerabilities across a set of dependencies.
/// Failures are returned as warnings, never printed and never silently
/// swallowed — the caller decides whether a degraded scan passes.
pub fn query_batch(deps: &[&Dependency]) -> OsvOutcome {
    let mut outcome = OsvOutcome {
        findings: Vec::new(),
        warnings: Vec::new(),
    };
    if deps.is_empty() {
        return outcome;
    }

    for chunk in deps.chunks(BATCH_SIZE) {
        match query_osv_batch(chunk) {
            Ok(findings) => outcome.findings.extend(findings),
            Err(e) => {
                outcome.warnings.push(format!(
                    "OSV query failed for {} dependencies: {} — these were NOT checked online",
                    chunk.len(),
                    e
                ));
            }
        }
    }

    outcome
}

fn query_osv_batch(deps: &[&Dependency]) -> Result<Vec<Finding>> {
    let queries: Vec<OsvQuery> = deps
        .iter()
        .map(|dep| OsvQuery {
            package: OsvPackage {
                name: dep.name.clone(),
                ecosystem: ecosystem_to_osv(dep.ecosystem),
            },
            version: dep.version.clone(),
        })
        .collect();

    let request = OsvBatchRequest { queries };

    let resp = osv_client()
        .post(OSV_BATCH_URL)
        .json(&request)
        .send()
        .context("OSV API request failed (30s timeout)")?;

    if !resp.status().is_success() {
        anyhow::bail!("OSV API returned HTTP {}", resp.status());
    }

    let batch_resp: OsvBatchResponse = resp.json().context("Failed to parse OSV response")?;

    let mut findings = Vec::new();

    for (i, result) in batch_resp.results.iter().enumerate() {
        let dep = &deps[i];
        for vuln in &result.vulns {
            findings.push(osv_vuln_to_finding(dep, vuln));
        }
    }

    Ok(findings)
}

fn osv_vuln_to_finding(dep: &Dependency, vuln: &OsvVuln) -> Finding {
    let severity = classify_osv_severity(vuln);
    let is_malware = vuln.id.starts_with("MAL-");
    let is_ghsa = vuln.id.starts_with("GHSA-");

    let kind = if is_malware {
        FindingKind::MaliciousPackage
    } else {
        FindingKind::SuspiciousRange
    };

    let description = vuln
        .summary
        .clone()
        .or_else(|| vuln.details.as_ref().map(|d| d.chars().take(200).collect()))
        .unwrap_or_else(|| vuln.id.clone());

    // Collect all references (not just 3)
    let references: Vec<String> = vuln
        .references
        .iter()
        .filter(|r| r.url_type == "ADVISORY" || r.url_type == "WEB")
        .map(|r| r.url.clone())
        .collect();

    // Primary advisory URL — OSV page is always available
    let advisory_url = if is_ghsa {
        format!("https://github.com/advisories/{}", vuln.id)
    } else {
        format!("https://osv.dev/vulnerability/{}", vuln.id)
    };

    let mut tags = Vec::new();
    tags.push("osv".to_string());
    if is_malware {
        tags.push("malware".to_string());
    }

    let cve = vuln.aliases.iter().find(|a| a.starts_with("CVE-")).cloned();

    // Generate remediation guidance based on finding type
    let remediation = generate_remediation(dep, vuln, is_malware, &cve);

    Finding {
        severity,
        package: dep.name.clone(),
        version: dep.version.clone(),
        kind,
        description: format!("[{}] {}", vuln.id, description),
        details: FindingDetails {
            cve,
            osv_id: Some(vuln.id.clone()),
            advisory_url: Some(advisory_url),
            references,
            tags,
            remediation: Some(remediation),
            ..Default::default()
        },
    }
}

/// Generate actionable remediation text for a finding
fn generate_remediation(
    dep: &Dependency,
    vuln: &OsvVuln,
    is_malware: bool,
    cve: &Option<String>,
) -> String {
    if is_malware {
        return format!(
            "IMMEDIATELY remove {}@{} from your project. \
             This package is confirmed malicious. \
             Run: npm uninstall {} / cargo rm {} / pip uninstall {} — \
             then audit your system for indicators of compromise. \
             Rotate any secrets or credentials that may have been exposed.",
            dep.name, dep.version, dep.name, dep.name, dep.name
        );
    }

    // Check if there's a fixed version in the affected ranges
    let fixed_version = vuln
        .affected
        .iter()
        .flat_map(|a| a.ranges.iter())
        .flat_map(|r| r.events.iter())
        .find_map(|e| e.get("fixed").and_then(|v| v.as_str()))
        .map(|s| s.to_string());

    match fixed_version {
        Some(fixed) => format!(
            "Upgrade {}@{} to {} or later. \
             Details: https://osv.dev/vulnerability/{}",
            dep.name, dep.version, fixed, vuln.id
        ),
        None => {
            let osv_url = format!("https://osv.dev/vulnerability/{}", vuln.id);
            format!(
                "Review {}@{} for known vulnerability {}. \
                 No fixed version identified — check {} for alternatives or patches.",
                dep.name,
                dep.version,
                cve.as_deref().unwrap_or(&vuln.id),
                osv_url
            )
        }
    }
}

fn classify_osv_severity(vuln: &OsvVuln) -> Severity {
    // MAL- prefixed IDs are malicious packages — always critical
    if vuln.id.starts_with("MAL-") {
        return Severity::Critical;
    }

    // Check database_specific severity
    if let Some(ref db) = vuln.database_specific {
        if let Some(ref sev) = db.severity {
            return match sev.to_uppercase().as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MODERATE" | "MEDIUM" => Severity::Medium,
                _ => Severity::Low,
            };
        }
    }

    // Check CVSS severity from severity array
    if let Some(ref severities) = vuln.severity {
        for s in severities {
            if let Some(score) = parse_cvss_score(&s.score) {
                return if score >= 9.0 {
                    Severity::Critical
                } else if score >= 7.0 {
                    Severity::High
                } else if score >= 4.0 {
                    Severity::Medium
                } else {
                    Severity::Low
                };
            }
        }
    }

    Severity::Medium // Default when severity unknown
}

/// Parse an OSV `severity[].score` into a numeric CVSS base score.
///
/// OSV publishes CVSS *vector strings* (`CVSS:3.1/AV:N/AC:L/.../A:H`),
/// not numbers — the previous implementation took the last `/` segment
/// (`A:H`) and failed to parse it, so every CVSS-scored vuln fell through
/// to the Medium default and critical CVEs did not fail CI.
fn parse_cvss_score(score: &str) -> Option<f64> {
    use std::str::FromStr;

    // Some databases do publish a bare number — accept it.
    if let Ok(n) = score.trim().parse::<f64>() {
        return Some(n);
    }

    if score.starts_with("CVSS:4") {
        return cvss::v4::Vector::from_str(score)
            .ok()
            .map(|v| v.score().value());
    }
    if score.starts_with("CVSS:3") {
        return cvss::v3::Base::from_str(score)
            .ok()
            .map(|b| b.score().value());
    }
    None
}

fn ecosystem_to_osv(eco: Ecosystem) -> String {
    match eco {
        Ecosystem::Npm => "npm".to_string(),
        Ecosystem::Cargo => "crates.io".to_string(),
        Ecosystem::Pip => "PyPI".to_string(),
        Ecosystem::Go => "Go".to_string(),
        Ecosystem::Composer => "Packagist".to_string(),
        Ecosystem::Bundler => "RubyGems".to_string(),
    }
}

// --- OSV API types ---

#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvBatchResult>,
}

#[derive(Deserialize)]
struct OsvBatchResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    severity: Option<Vec<OsvSeverity>>,
    #[serde(default)]
    database_specific: Option<OsvDbSpecific>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct OsvReference {
    #[serde(rename = "type", default)]
    url_type: String,
    url: String,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(default)]
    score: String,
}

#[derive(Deserialize)]
struct OsvDbSpecific {
    #[serde(default)]
    severity: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(id: &str, db_severity: Option<&str>, cvss: Option<&str>) -> OsvVuln {
        OsvVuln {
            id: id.to_string(),
            summary: None,
            details: None,
            aliases: vec![],
            references: vec![],
            severity: cvss.map(|s| {
                vec![OsvSeverity {
                    score: s.to_string(),
                }]
            }),
            database_specific: db_severity.map(|s| OsvDbSpecific {
                severity: Some(s.to_string()),
            }),
            affected: vec![],
        }
    }

    #[test]
    fn cvss_vector_strings_parse_to_scores() {
        // Real-world CVSS 3.1 vector for a 9.8 critical
        let score =
            parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").expect("should parse");
        assert!((score - 9.8).abs() < 0.05, "got {}", score);

        // Medium-ish vector
        let score =
            parse_cvss_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N").expect("should parse");
        assert!((3.0..7.0).contains(&score), "got {}", score);

        // Bare numeric scores still accepted
        assert_eq!(parse_cvss_score("7.5"), Some(7.5));

        // Garbage does not parse (and must not panic)
        assert_eq!(parse_cvss_score("A:H"), None);
    }

    #[test]
    fn classify_critical_cve_from_cvss_vector() {
        // No database_specific severity — classification must come from
        // the CVSS vector. This was the bug: it used to fall through to
        // Medium and exit 2 instead of 1.
        let v = vuln(
            "GHSA-xxxx",
            None,
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        );
        assert_eq!(classify_osv_severity(&v), Severity::Critical);
    }

    #[test]
    fn classify_mal_prefix_is_always_critical() {
        let v = vuln("MAL-2026-1234", None, None);
        assert_eq!(classify_osv_severity(&v), Severity::Critical);
    }

    #[test]
    fn classify_database_specific_takes_precedence() {
        let v = vuln("GHSA-yyyy", Some("HIGH"), None);
        assert_eq!(classify_osv_severity(&v), Severity::High);
        let v = vuln("GHSA-zzzz", Some("MODERATE"), None);
        assert_eq!(classify_osv_severity(&v), Severity::Medium);
    }

    #[test]
    fn classify_unknown_defaults_to_medium() {
        let v = vuln("GHSA-unknown", None, None);
        assert_eq!(classify_osv_severity(&v), Severity::Medium);
    }
}
