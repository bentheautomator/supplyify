//! Obfuscation heuristic: deep content scan of *flagged* packages.
//!
//! Runs only on packages another layer already flagged (plus their
//! installed postinstall scripts) — never the whole node_modules — so it
//! stays fast and low-noise. Looks for the payload-hiding techniques used
//! by real droppers: giant base64 blobs, hex-escape runs, charcode
//! assembly, eval-of-decoded-data, and (highest confidence) known C2
//! addresses from the indicator database appearing in package source.

use std::path::Path;
use std::sync::OnceLock;

use crate::{Finding, FindingDetails, FindingKind, Severity};

/// Cap on files examined per package and bytes per file — flagged
/// packages are small; a cap keeps the layer bounded on weird ones.
const MAX_FILES_PER_PKG: usize = 50;
const MAX_FILE_BYTES: u64 = 1_000_000;

struct Patterns {
    base64_blob: regex::Regex,
    hex_run: regex::Regex,
    charcode_assembly: regex::Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        // A 200+ char base64 literal is data smuggling, not config
        base64_blob: regex::Regex::new(r#"[A-Za-z0-9+/]{200,}={0,2}"#).unwrap(),
        // Long runs of \xNN escapes hide strings from grep
        hex_run: regex::Regex::new(r#"(\\x[0-9a-fA-F]{2}){20,}"#).unwrap(),
        // String.fromCharCode(112,108,97,...) payload assembly
        charcode_assembly: regex::Regex::new(
            r#"String\.fromCharCode\(\s*[0-9]{1,3}\s*(,\s*[0-9]{1,3}\s*){15,}"#,
        )
        .unwrap(),
    })
}

/// Scan the installed source of `flagged` npm packages for obfuscation
/// markers and known C2 infrastructure.
pub fn scan_flagged(
    project_path: &Path,
    flagged: &[String],
    c2_addresses: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let node_modules = project_path.join("node_modules");
    if !node_modules.exists() {
        return findings;
    }

    for pkg in flagged {
        let pkg_dir = node_modules.join(pkg);
        if !pkg_dir.is_dir() {
            continue;
        }
        if let Some(finding) = scan_package_dir(pkg, &pkg_dir, c2_addresses) {
            findings.push(finding);
        }
    }

    findings
}

fn scan_package_dir(pkg: &str, dir: &Path, c2_addresses: &[String]) -> Option<Finding> {
    let mut markers: Vec<String> = Vec::new();
    let mut c2_hits: Vec<String> = Vec::new();
    let mut examined = 0usize;

    for entry in walkdir::WalkDir::new(dir)
        .max_depth(4)
        .into_iter()
        .filter_entry(|e| e.file_name() != "node_modules")
        .flatten()
    {
        if examined >= MAX_FILES_PER_PKG {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let is_code = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| matches!(e, "js" | "cjs" | "mjs" | "ts" | "json"))
            .unwrap_or(false);
        if !is_code {
            continue;
        }
        if entry
            .metadata()
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(true)
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        examined += 1;

        let rel = path.strip_prefix(dir).unwrap_or(path).display();
        let p = patterns();

        for c2 in c2_addresses {
            // Match the host part — "host:port" indicators also match on host
            let host = crate::c2_host(c2);
            if !host.is_empty() && content.contains(host) {
                c2_hits.push(format!("{} contains C2 address {}", rel, host));
            }
        }
        if p.base64_blob.is_match(&content) {
            markers.push(format!("{}: large base64 blob", rel));
        }
        if p.hex_run.is_match(&content) {
            markers.push(format!("{}: long hex-escape run", rel));
        }
        if p.charcode_assembly.is_match(&content) {
            markers.push(format!("{}: charcode string assembly", rel));
        }
        if (content.contains("eval(") || content.contains("new Function"))
            && (content.contains("atob(") || content.contains("Buffer.from("))
        {
            markers.push(format!("{}: eval of decoded data", rel));
        }
    }

    if c2_hits.is_empty() && markers.is_empty() {
        return None;
    }

    let version = read_installed_version(dir).unwrap_or_else(|| "unknown".to_string());

    if !c2_hits.is_empty() {
        // Known C2 infrastructure inside package source is as close to
        // proof of compromise as a static scan gets.
        return Some(Finding {
            severity: Severity::Critical,
            package: pkg.to_string(),
            version,
            kind: FindingKind::Heuristic("c2_in_source".to_string()),
            description: format!(
                "Known C2 infrastructure referenced in package source: {}",
                c2_hits.join("; ")
            ),
            details: FindingDetails {
                c2: c2_hits,
                tags: vec![
                    "heuristic".to_string(),
                    "obfuscation".to_string(),
                    "c2".to_string(),
                ],
                remediation: Some(format!(
                    "IMMEDIATELY remove {} and treat this machine as compromised. \
                     Package source references known command-and-control infrastructure. \
                     Rotate all credentials accessible from this environment.",
                    pkg
                )),
                ..Default::default()
            },
        });
    }

    markers.truncate(8);
    Some(Finding {
        severity: Severity::High,
        package: pkg.to_string(),
        version,
        kind: FindingKind::Heuristic("obfuscation".to_string()),
        description: format!("Obfuscated payload markers: {}", markers.join("; ")),
        details: FindingDetails {
            tags: vec!["heuristic".to_string(), "obfuscation".to_string()],
            remediation: Some(format!(
                "Manually review the listed files in node_modules/{} before trusting \
                 this package — obfuscation in an already-flagged package is a strong \
                 compromise signal.",
                pkg
            )),
            ..Default::default()
        },
    })
}

fn read_installed_version(pkg_dir: &Path) -> Option<String> {
    let content = std::fs::read_to_string(pkg_dir.join("package.json")).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json.get("version")?.as_str().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkg(dir: &Path, name: &str, files: &[(&str, &str)]) {
        let pkg_dir = dir.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!(r#"{{"name":"{}","version":"9.9.9"}}"#, name),
        )
        .unwrap();
        for (fname, content) in files {
            std::fs::write(pkg_dir.join(fname), content).unwrap();
        }
    }

    #[test]
    fn detects_c2_address_in_source() {
        let dir = tempfile::tempdir().unwrap();
        make_pkg(
            dir.path(),
            "evil-pkg",
            &[("index.js", "const c = net.connect(8000, 'sfrclak.com');")],
        );

        let findings = scan_flagged(
            dir.path(),
            &["evil-pkg".to_string()],
            &["sfrclak.com:8000".to_string()],
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].kind.name(), "c2_in_source");
    }

    #[test]
    fn detects_base64_blob() {
        let dir = tempfile::tempdir().unwrap();
        let blob = "A".repeat(250);
        make_pkg(
            dir.path(),
            "shady",
            &[("payload.js", &format!("var data = \"{}\";", blob))],
        );

        let findings = scan_flagged(dir.path(), &["shady".to_string()], &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].description.contains("base64"));
    }

    #[test]
    fn detects_eval_of_decoded_data() {
        let dir = tempfile::tempdir().unwrap();
        make_pkg(
            dir.path(),
            "decoder",
            &[("index.js", "eval(Buffer.from(x, 'base64').toString());")],
        );

        let findings = scan_flagged(dir.path(), &["decoder".to_string()], &[]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("eval of decoded data"));
    }

    #[test]
    fn clean_package_produces_nothing() {
        let dir = tempfile::tempdir().unwrap();
        make_pkg(
            dir.path(),
            "fine",
            &[(
                "index.js",
                "module.exports = function add(a, b) { return a + b; };",
            )],
        );
        assert!(scan_flagged(dir.path(), &["fine".to_string()], &[]).is_empty());
    }

    #[test]
    fn unflagged_packages_not_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let blob = "A".repeat(250);
        make_pkg(dir.path(), "shady", &[("p.js", &format!("\"{}\"", blob))]);
        // shady exists but was never flagged — targeted layer skips it
        assert!(scan_flagged(dir.path(), &[], &[]).is_empty());
    }
}
