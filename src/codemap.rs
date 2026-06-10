//! Layer 3: targeted deep analysis of flagged packages via the `codemap`
//! binary (the same tool gitguard gates ships with).
//!
//! Deliberately narrow: codemap runs ONLY on the installed source of
//! packages another layer already flagged — never the whole dependency
//! tree. If the binary isn't installed the layer is skipped silently
//! (it's an enhancer, not a base layer).

use std::path::Path;
use std::process::Command;

use crate::{Finding, FindingDetails, FindingKind, Severity};

const CODEMAP_BIN: &str = "codemap";
/// Bound the layer: deep analysis is for confirmation, not bulk scanning
const MAX_PACKAGES: usize = 5;

pub fn is_available() -> bool {
    Command::new(CODEMAP_BIN)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `codemap security` against the installed source of flagged npm
/// packages. Returns confirmation findings for HIGH/CRITICAL results.
pub fn scan_flagged(project_path: &Path, flagged: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let node_modules = project_path.join("node_modules");
    if !node_modules.exists() || flagged.is_empty() || !is_available() {
        return findings;
    }

    for pkg in flagged.iter().take(MAX_PACKAGES) {
        let pkg_dir = node_modules.join(pkg);
        if !pkg_dir.is_dir() {
            continue;
        }
        let Ok(out) = Command::new(CODEMAP_BIN)
            .arg("security")
            .arg(&pkg_dir)
            .args(["-o", "agent"])
            .output()
        else {
            continue;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if let Some((severity, message)) = parse_security_line(line) {
                findings.push(Finding {
                    severity,
                    package: pkg.clone(),
                    version: "installed".to_string(),
                    kind: FindingKind::Heuristic("codemap".to_string()),
                    description: format!("codemap security: {}", message),
                    details: FindingDetails {
                        tags: vec!["codemap".to_string(), "layer3".to_string()],
                        ..Default::default()
                    },
                });
            }
        }
    }

    findings
}

/// Parse a codemap security line: `CWE-95|CRITICAL|file:line|message|hint`.
/// Field-marker matching, not substring matching — symbol names like
/// `is_critical` must not false-flag (same lesson as gitguard PR #18).
fn parse_security_line(line: &str) -> Option<(Severity, String)> {
    let mut fields = line.split('|');
    let cwe = fields.next()?.trim();
    if !cwe.to_ascii_uppercase().starts_with("CWE-") {
        return None;
    }
    let severity = match fields.next()?.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        _ => Severity::Low,
    };
    // Only surface blocking-tier confirmations from Layer 3
    if severity < Severity::High {
        return None;
    }
    let location = fields.next().unwrap_or("").trim();
    let message = fields.next().unwrap_or("").trim();
    Some((severity, format!("{} {} ({})", cwe, message, location)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_blocking_security_lines() {
        let (sev, msg) = parse_security_line(
            "CWE-95|CRITICAL|index.js:42|Code injection via eval|Use safe alternatives",
        )
        .unwrap();
        assert_eq!(sev, Severity::Critical);
        assert!(msg.contains("CWE-95"));
        assert!(msg.contains("index.js:42"));
    }

    #[test]
    fn skips_non_blocking_and_non_findings() {
        // Medium findings are not surfaced by Layer 3
        assert!(parse_security_line("CWE-20|MEDIUM|a.js:1|Input validation|x").is_none());
        // Headers, summaries, symbol names must not false-flag
        assert!(parse_security_line("SUMMARY|0 critical").is_none());
        assert!(parse_security_line("fn is_critical() {").is_none());
        assert!(parse_security_line("").is_none());
    }
}
