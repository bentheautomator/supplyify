//! SARIF 2.1.0 output — GitHub Code Scanning / Advanced Security ingest
//! this directly (`-f sarif -o supplyify.sarif` + upload-sarif action).

use serde_json::json;
use std::collections::BTreeMap;

use crate::{ScanResult, Severity};

pub fn format(results: &[ScanResult]) -> String {
    // Collect distinct rules (finding kinds) across all results
    let mut rules: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut sarif_results = Vec::new();

    for result in results {
        for finding in &result.findings {
            let rule_id = finding.kind.name().to_string();
            rules.entry(rule_id.clone()).or_insert_with(|| {
                json!({
                    "id": rule_id,
                    "shortDescription": { "text": rule_description(&rule_id) },
                })
            });

            let uri = finding
                .details
                .lockfile_path
                .clone()
                .unwrap_or_else(|| result.project_path.clone());

            let mut message = format!(
                "{}@{}: {}",
                finding.package, finding.version, finding.description
            );
            if let Some(ref remediation) = finding.details.remediation {
                message.push_str(&format!(" Remediation: {}", remediation));
            }

            sarif_results.push(json!({
                "ruleId": finding.kind.name(),
                "level": level(finding.severity),
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri }
                    }
                }],
                "properties": {
                    "severity": finding.severity.to_string(),
                    "package": finding.package,
                    "version": finding.version,
                    "tags": finding.details.tags,
                }
            }));
        }
    }

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "supplyify",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/bentheautomator/supplyify",
                    "rules": rules.into_values().collect::<Vec<_>>(),
                }
            },
            "results": sarif_results,
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn rule_description(rule_id: &str) -> String {
    match rule_id {
        "malicious_version" => "Known malicious package version".to_string(),
        "malicious_package" => "Known malicious package".to_string(),
        "suspicious_range" => "Version published during a compromise window".to_string(),
        "postinstall" => "Suspicious lifecycle script".to_string(),
        "version_anomaly" => "Anomalous version string".to_string(),
        "obfuscation" => "Obfuscated payload markers in package source".to_string(),
        "c2_in_source" => "Known C2 infrastructure in package source".to_string(),
        "c2_in_lifecycle_script" => "Known C2 infrastructure in lifecycle script".to_string(),
        "dependency_downgrade" => "Version downgrade since last commit".to_string(),
        "new_dependencies" => "New dependencies since last commit".to_string(),
        "codemap" => "codemap deep-analysis finding".to_string(),
        other => format!("supplyify finding: {}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, FindingDetails, FindingKind};

    #[test]
    fn produces_valid_sarif_shape() {
        let result = ScanResult {
            project_path: ".".into(),
            ecosystems: vec![crate::Ecosystem::Npm],
            dep_count: 1,
            findings: vec![Finding {
                severity: Severity::Critical,
                package: "axios".into(),
                version: "1.14.1".into(),
                kind: FindingKind::MaliciousVersion,
                description: "bad".into(),
                details: FindingDetails {
                    lockfile_path: Some("package-lock.json".into()),
                    ..Default::default()
                },
            }],
            duration_ms: 1,
            warnings: vec![],
            degraded: false,
            ignored_count: 0,
        };

        let sarif: serde_json::Value = serde_json::from_str(&format(&[result])).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        let run = &sarif["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "supplyify");
        assert_eq!(run["results"][0]["ruleId"], "malicious_version");
        assert_eq!(run["results"][0]["level"], "error");
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "package-lock.json"
        );
    }
}
