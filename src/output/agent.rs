use crate::ScanResult;

/// Format version for the agent contract. Bump when the line grammar
/// changes incompatibly — consumers (gitguard, codemap) parse this.
const AGENT_FORMAT_VERSION: &str = "1";

pub fn format(results: &[ScanResult]) -> String {
    let mut out = String::new();

    // Versioned header: tool|tool-version|format-version
    out.push_str(&format!(
        "SUPPLYIFY|{}|{}\n",
        env!("CARGO_PKG_VERSION"),
        AGENT_FORMAT_VERSION
    ));

    for result in results {
        out.push_str("CMD|scan\n");
        out.push_str(&format!("PROJECT|{}\n", result.project_path));
        let ecosystems: Vec<String> = result.ecosystems.iter().map(|e| e.to_string()).collect();
        out.push_str(&format!("ECOSYSTEM|{}\n", ecosystems.join(",")));
        out.push_str(&format!("DEPS|{}\n", result.dep_count));
        out.push_str("---\n");

        for finding in &result.findings {
            out.push_str(&format!(
                "FINDING|{}|{}|{}|{}|{}\n",
                finding.severity,
                finding.package,
                finding.version,
                finding.kind.name(),
                finding.description.replace('\n', " ")
            ));

            for c2 in &finding.details.c2 {
                out.push_str(&format!("C2|{}\n", c2));
            }
        }

        // Degradation is part of the contract: consumers must be able to
        // tell "scanned clean" from "couldn't fully scan"
        for w in &result.warnings {
            out.push_str(&format!("WARNING|{}\n", w.replace('\n', " ")));
        }
        if result.degraded {
            out.push_str("DEGRADED|true\n");
        }
        if result.ignored_count > 0 {
            out.push_str(&format!("IGNORED|{}\n", result.ignored_count));
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
