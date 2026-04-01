use crate::{Finding, FindingDetails, FindingKind, Severity};
use std::path::Path;

/// Suspicious patterns in postinstall scripts
const SUSPICIOUS_PATTERNS: &[&str] = &[
    "curl ",
    "wget ",
    "powershell",
    "base64",
    "Buffer.from",
    "atob",
    "child_process",
    "eval(",
    "Function(",
    "new Function",
    "http://",
    "https://",
    "net.connect",
    "dgram",
];

/// Scan node_modules for suspicious postinstall scripts
pub fn scan(project_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let node_modules = project_path.join("node_modules");

    if !node_modules.exists() {
        return findings;
    }

    // Walk immediate children of node_modules (packages)
    let entries = match std::fs::read_dir(&node_modules) {
        Ok(e) => e,
        Err(_) => return findings,
    };

    for entry in entries.flatten() {
        let pkg_dir = entry.path();
        let pkg_json = pkg_dir.join("package.json");

        if !pkg_json.exists() {
            // Check scoped packages (@scope/pkg)
            if entry.file_name().to_string_lossy().starts_with('@') {
                if let Ok(scoped_entries) = std::fs::read_dir(&pkg_dir) {
                    for scoped_entry in scoped_entries.flatten() {
                        let scoped_pkg_json = scoped_entry.path().join("package.json");
                        if scoped_pkg_json.exists() {
                            if let Some(finding) = check_package_json(&scoped_pkg_json) {
                                findings.push(finding);
                            }
                        }
                    }
                }
            }
            continue;
        }

        if let Some(finding) = check_package_json(&pkg_json) {
            findings.push(finding);
        }
    }

    findings
}

/// Check a single package.json for suspicious lifecycle scripts
fn check_package_json(path: &Path) -> Option<Finding> {
    let content = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;

    let name = json
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("unknown");
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0");

    let scripts = json.get("scripts")?;

    let lifecycle_keys = ["preinstall", "install", "postinstall"];
    let mut suspicious_scripts = Vec::new();

    for key in &lifecycle_keys {
        if let Some(script) = scripts.get(*key).and_then(|s| s.as_str()) {
            let matched: Vec<&&str> = SUSPICIOUS_PATTERNS
                .iter()
                .filter(|p| script.contains(**p))
                .collect();

            if !matched.is_empty() {
                suspicious_scripts.push(format!(
                    "{}: {} (matches: {})",
                    key,
                    script,
                    matched.iter().map(|p| **p).collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }

    if suspicious_scripts.is_empty() {
        return None;
    }

    let severity = if suspicious_scripts
        .iter()
        .any(|s| s.contains("base64") || s.contains("eval(") || s.contains("Function("))
    {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(Finding {
        severity,
        package: name.to_string(),
        version: version.to_string(),
        kind: FindingKind::Heuristic("postinstall".to_string()),
        description: format!(
            "Suspicious lifecycle script: {}",
            suspicious_scripts.join("; ")
        ),
        details: FindingDetails {
            tags: vec!["heuristic".to_string(), "postinstall".to_string()],
            ..Default::default()
        },
    })
}
