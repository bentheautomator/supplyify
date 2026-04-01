use crate::{FindingKind, ScanResult, Severity};
use colored::Colorize;

pub fn format(results: &[ScanResult]) -> String {
    let mut out = String::new();

    for result in results {
        out.push_str(&format!("supplyify — scanning {}\n\n", result.project_path));

        if result.findings.is_empty() {
            out.push_str(&format!("{}  No threats detected\n", "✓".green()));
        } else {
            for finding in &result.findings {
                let sev_str = match finding.severity {
                    Severity::Critical => "CRITICAL".red().bold().to_string(),
                    Severity::High => "HIGH".yellow().bold().to_string(),
                    Severity::Medium => "WARNING".cyan().to_string(),
                    Severity::Low => "INFO".dimmed().to_string(),
                };

                let kind_str = match &finding.kind {
                    FindingKind::MaliciousVersion => "malicious version",
                    FindingKind::MaliciousPackage => "malicious package",
                    FindingKind::SuspiciousRange => "suspicious range",
                    FindingKind::Heuristic(h) => h.as_str(),
                };

                out.push_str(&format!(
                    "{:<10} {}@{} — {} ({})\n",
                    sev_str,
                    finding.package.cyan(),
                    finding.version.green(),
                    finding.description,
                    kind_str,
                ));

                if !finding.details.c2.is_empty() {
                    out.push_str(&format!(
                        "  ├─ C2: {}\n",
                        finding.details.c2.join(", ").red()
                    ));
                }
                if !finding.details.references.is_empty() {
                    for r in &finding.details.references {
                        out.push_str(&format!("  ├─ Ref: {}\n", r.dimmed()));
                    }
                }
                if !finding.details.tags.is_empty() {
                    out.push_str(&format!(
                        "  └─ Tags: {}\n",
                        finding.details.tags.join(", ").yellow()
                    ));
                }
                out.push('\n');
            }
        }

        let (critical, high, medium, low) = result.count_by_severity();
        let ecosystems: Vec<String> = result.ecosystems.iter().map(|e| e.to_string()).collect();

        out.push_str(&format!(
            "──────────────────────────────────\n\
             Scanned: {} ({}) | {} deps | {}ms\n\
             Results: {} critical, {} high, {} medium, {} low\n",
            result.project_path,
            if ecosystems.is_empty() {
                "no lockfiles".to_string()
            } else {
                ecosystems.join(", ")
            },
            result.dep_count,
            result.duration_ms,
            critical,
            high,
            medium,
            low,
        ));
    }

    out
}
