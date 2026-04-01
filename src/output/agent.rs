use crate::{FindingKind, ScanResult};

pub fn format(results: &[ScanResult]) -> String {
    let mut out = String::new();

    for result in results {
        out.push_str("CMD|scan\n");
        out.push_str(&format!("PROJECT|{}\n", result.project_path));
        let ecosystems: Vec<String> = result.ecosystems.iter().map(|e| e.to_string()).collect();
        out.push_str(&format!("ECOSYSTEM|{}\n", ecosystems.join(",")));
        out.push_str(&format!("DEPS|{}\n", result.dep_count));
        out.push_str("---\n");

        for finding in &result.findings {
            let kind = match &finding.kind {
                FindingKind::MaliciousVersion => "malicious_version",
                FindingKind::MaliciousPackage => "malicious_package",
                FindingKind::SuspiciousRange => "suspicious_range",
                FindingKind::Heuristic(h) => h.as_str(),
            };
            out.push_str(&format!(
                "FINDING|{}|{}|{}|{}|{}\n",
                finding.severity, finding.package, finding.version, kind, finding.description
            ));

            for c2 in &finding.details.c2 {
                out.push_str(&format!("C2|{}\n", c2));
            }
        }

        out.push_str("---\n");
        let (c, h, m, l) = result.count_by_severity();
        out.push_str(&format!(
            "SUMMARY|{} critical, {} high, {} medium, {} low | {}\n",
            c,
            h,
            m,
            l,
            result.duration_display()
        ));
    }

    out
}
