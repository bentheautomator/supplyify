//! Project policy: `.supplyify.toml` in the project root.
//!
//! Without an ignore mechanism, one noisy finding makes CI exit non-zero
//! forever, teams add `|| true`, and the gate is dead. Rules are scoped
//! (package + optional version + optional kind) and can carry an expiry
//! date so suppressions don't outlive their justification.
//!
//! ```toml
//! [[ignore]]
//! package = "legacy-pkg"
//! version = "0.0.0-internal"     # optional — any version if omitted
//! kind = "version_anomaly"        # optional — any kind if omitted
//! reason = "internal build tag, not a registry package"
//! expires = "2026-12-31"          # optional — rule ignored after this date
//! ```

use serde::Deserialize;
use std::path::Path;

use crate::Finding;

pub const POLICY_FILE: &str = ".supplyify.toml";

#[derive(Debug, Default, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub ignore: Vec<IgnoreRule>,
}

#[derive(Debug, Deserialize)]
pub struct IgnoreRule {
    pub package: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// ISO date (YYYY-MM-DD). Rule stops applying after this date.
    #[serde(default)]
    pub expires: Option<String>,
}

impl Policy {
    /// Load policy from `<project>/.supplyify.toml`. Returns (policy,
    /// warnings) — a malformed policy file is surfaced, not ignored.
    pub fn load(project_path: &Path) -> (Self, Vec<String>) {
        let path = project_path.join(POLICY_FILE);
        if !path.exists() {
            return (Self::default(), vec![]);
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match toml::from_str::<Policy>(&content) {
                Ok(policy) => (policy, vec![]),
                Err(e) => (
                    Self::default(),
                    vec![format!(
                        "{}: parse failed ({}) — no findings ignored",
                        path.display(),
                        e
                    )],
                ),
            },
            Err(e) => (
                Self::default(),
                vec![format!("{}: read failed ({})", path.display(), e)],
            ),
        }
    }

    /// Split findings into (kept, ignored_count). Expired rules don't apply.
    pub fn apply(&self, findings: Vec<Finding>) -> (Vec<Finding>, usize) {
        if self.ignore.is_empty() {
            return (findings, 0);
        }
        let today = today_iso();
        let before = findings.len();
        let kept: Vec<Finding> = findings
            .into_iter()
            .filter(|f| !self.ignore.iter().any(|r| r.matches(f, &today)))
            .collect();
        let ignored = before - kept.len();
        (kept, ignored)
    }
}

impl IgnoreRule {
    fn matches(&self, finding: &Finding, today: &str) -> bool {
        if let Some(expires) = &self.expires {
            // ISO dates compare correctly as strings
            if today.as_bytes() > expires.as_bytes() {
                return false;
            }
        }
        if self.package != finding.package {
            return false;
        }
        if let Some(v) = &self.version {
            if v != &finding.version {
                return false;
            }
        }
        if let Some(k) = &self.kind {
            if k != finding.kind.name() {
                return false;
            }
        }
        true
    }
}

/// Today's date as YYYY-MM-DD, derived from the system clock without a
/// date-crate dependency (Howard Hinnant's civil-from-days algorithm).
fn today_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FindingDetails, FindingKind, Severity};

    fn finding(package: &str, version: &str, kind: &str) -> Finding {
        Finding {
            severity: Severity::Medium,
            package: package.into(),
            version: version.into(),
            kind: FindingKind::Heuristic(kind.into()),
            description: "test".into(),
            details: FindingDetails::default(),
        }
    }

    fn policy(toml_str: &str) -> Policy {
        toml::from_str(toml_str).unwrap()
    }

    #[test]
    fn ignores_matching_finding() {
        let p = policy(
            r#"
[[ignore]]
package = "legacy"
kind = "version_anomaly"
reason = "internal build tag"
"#,
        );
        let (kept, ignored) = p.apply(vec![
            finding("legacy", "0.0.0-x", "version_anomaly"),
            finding("other", "1.0.0", "version_anomaly"),
        ]);
        assert_eq!(ignored, 1);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].package, "other");
    }

    #[test]
    fn version_scoping() {
        let p = policy(
            r#"
[[ignore]]
package = "pkg"
version = "1.0.0"
"#,
        );
        let (kept, ignored) = p.apply(vec![
            finding("pkg", "1.0.0", "x"),
            finding("pkg", "2.0.0", "x"),
        ]);
        assert_eq!(ignored, 1);
        assert_eq!(kept[0].version, "2.0.0");
    }

    #[test]
    fn expired_rule_does_not_apply() {
        let p = policy(
            r#"
[[ignore]]
package = "pkg"
expires = "2020-01-01"
"#,
        );
        let (kept, ignored) = p.apply(vec![finding("pkg", "1.0.0", "x")]);
        assert_eq!(ignored, 0);
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn future_expiry_applies() {
        let p = policy(
            r#"
[[ignore]]
package = "pkg"
expires = "2999-01-01"
"#,
        );
        let (_, ignored) = p.apply(vec![finding("pkg", "1.0.0", "x")]);
        assert_eq!(ignored, 1);
    }

    #[test]
    fn malformed_policy_is_a_warning_not_silence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(POLICY_FILE), "[[ignore]]\nnot valid").unwrap();
        let (policy, warnings) = Policy::load(dir.path());
        assert!(policy.ignore.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("parse failed"));
    }

    #[test]
    fn civil_from_days_sanity() {
        // 2026-06-10 is 20614 days after epoch
        assert_eq!(civil_from_days(20614), (2026, 6, 10));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }
}
