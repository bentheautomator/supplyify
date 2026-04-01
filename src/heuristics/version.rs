use crate::{Dependency, Finding, FindingDetails, FindingKind, Severity};

/// Scan dependencies for version anomalies
pub fn scan(deps: &[&Dependency]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for dep in deps {
        // Check for non-semver versions
        if semver::Version::parse(&dep.version).is_err() {
            findings.push(Finding {
                severity: Severity::Medium,
                package: dep.name.clone(),
                version: dep.version.clone(),
                kind: FindingKind::Heuristic("version_anomaly".to_string()),
                description: format!("Non-semver version string: {}", dep.version),
                details: FindingDetails {
                    tags: vec!["heuristic".to_string(), "version".to_string()],
                    ..Default::default()
                },
            });
        }
    }

    findings
}
