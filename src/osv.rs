use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{Dependency, Ecosystem, Finding, FindingDetails, FindingKind, Severity};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const BATCH_SIZE: usize = 1000; // OSV API limit per batch

/// Query OSV.dev for known vulnerabilities across a set of dependencies
pub fn query_batch(deps: &[&Dependency]) -> Vec<Finding> {
    if deps.is_empty() {
        return Vec::new();
    }

    let mut all_findings = Vec::new();

    // Process in batches of BATCH_SIZE
    for chunk in deps.chunks(BATCH_SIZE) {
        match query_osv_batch(chunk) {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => {
                eprintln!("  Warning: OSV query failed: {}", e);
                break;
            }
        }
    }

    all_findings
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

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(OSV_BATCH_URL)
        .json(&request)
        .header("User-Agent", "supplyify")
        .send()
        .context("OSV API request failed")?;

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

fn parse_cvss_score(cvss: &str) -> Option<f64> {
    // CVSS vector strings end with score or contain it
    // Try to extract numeric score
    cvss.split('/').next_back()?.parse().ok()
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
