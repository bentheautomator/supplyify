pub mod ecosystems;
pub mod heuristics;
pub mod indicators;
pub mod osv;
pub mod output;
pub mod plugin;
pub mod scanner;
pub mod sweep;

/// Global configuration derived from CLI flags
#[derive(Clone)]
pub struct Config {
    pub format: String,
    pub output: Option<String>,
    pub quiet: bool,
    pub no_codemap: bool,
    pub no_heuristics: bool,
    pub no_osv: bool,
    /// Strict mode: a degraded scan (OSV unreachable, unparseable lockfile)
    /// exits non-zero (exit 3) instead of silently passing as clean.
    /// Integration contract for gitguard's pre-push lefthook (#293).
    pub strict: bool,
    /// Minimum severity that causes a non-zero exit. Defaults to High.
    /// `--fail-on critical` lets High findings warn without blocking.
    pub fail_on: Severity,
}

/// Severity levels for findings
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!(
                "unknown severity '{}': expected one of low|medium|high|critical",
                other
            )),
        }
    }
}

/// Supported package ecosystems
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Cargo,
    Pip,
    Go,
    Composer,
    Bundler,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::Cargo => write!(f, "cargo"),
            Ecosystem::Pip => write!(f, "pip"),
            Ecosystem::Go => write!(f, "go"),
            Ecosystem::Composer => write!(f, "composer"),
            Ecosystem::Bundler => write!(f, "bundler"),
        }
    }
}

/// A resolved dependency from a lockfile
#[derive(Debug, Clone, serde::Serialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
}

/// A finding from the scan
#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub package: String,
    pub version: String,
    pub kind: FindingKind,
    pub description: String,
    pub details: FindingDetails,
}

/// What type of finding
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    MaliciousVersion,
    MaliciousPackage,
    SuspiciousRange,
    Heuristic(String),
}

/// Additional details attached to a finding
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FindingDetails {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub c2: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub osv_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lockfile_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Result of scanning a single project
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanResult {
    pub project_path: String,
    pub ecosystems: Vec<Ecosystem>,
    pub dep_count: usize,
    pub findings: Vec<Finding>,
    pub duration_ms: u128,
    /// Whether the scan was degraded (indicator DB unloadable, OSV unreachable,
    /// or lockfile parse errors). Under `strict` mode this triggers exit 3.
    #[serde(default)]
    pub degraded: bool,
}

impl ScanResult {
    pub fn duration_display(&self) -> String {
        if self.duration_ms >= 60_000 {
            format!("{:.1}m", self.duration_ms as f64 / 60_000.0)
        } else if self.duration_ms >= 1_000 {
            format!("{:.1}s", self.duration_ms as f64 / 1_000.0)
        } else {
            format!("{}ms", self.duration_ms)
        }
    }

    /// Legacy exit code, preserved verbatim from pre-0.3.0 so in-process
    /// consumers that call this directly see the same verdict they always
    /// did:
    ///   0 — no findings at all
    ///   1 — any finding at High or Critical
    ///   2 — findings present but all below High (the "was anything found?"
    ///       signal older CI configs rely on)
    ///
    /// The v0.3.0 CLI (`scan` / `sweep`) uses `exit_code_v3` with the
    /// user's `--fail-on` + `--strict` flags, which lets shell gates treat
    /// below-fail-on findings as pass (exit 0). Do NOT call this from new
    /// code — call `exit_code_v3(fail_on, strict)` directly.
    #[deprecated(
        since = "0.3.0",
        note = "call exit_code_v3(fail_on, strict) instead; this preserves pre-0.3.0 semantics for in-process consumers"
    )]
    pub fn exit_code(&self) -> i32 {
        if self.findings.iter().any(|f| f.severity >= Severity::High) {
            1
        } else if !self.findings.is_empty() {
            2
        } else {
            0
        }
    }

    /// v0.3.0 exit code with configurable `fail_on` severity and `strict`
    /// gating for degraded scans. Exit codes:
    ///   0 — clean OR all findings are strictly below `fail_on` (do not
    ///       block — the whole point of --fail-on is to tell the caller
    ///       what severity blocks; anything below that surfaces in the
    ///       report but exits 0 so shell gates pass)
    ///   1 — one or more findings at or above `fail_on`
    ///   3 — strict mode AND scan was degraded (no findings gate applies
    ///       because coverage was incomplete)
    pub fn exit_code_v3(&self, fail_on: Severity, strict: bool) -> i32 {
        if strict && self.degraded {
            return 3;
        }
        if self.findings.iter().any(|f| f.severity >= fail_on) {
            1
        } else {
            0
        }
    }

    pub fn count_by_severity(&self) -> (usize, usize, usize, usize) {
        let critical = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();
        (critical, high, medium, low)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(findings: Vec<Severity>, degraded: bool) -> ScanResult {
        ScanResult {
            project_path: "x".into(),
            ecosystems: vec![],
            dep_count: 0,
            findings: findings
                .into_iter()
                .map(|s| Finding {
                    severity: s,
                    package: "p".into(),
                    version: "1".into(),
                    kind: FindingKind::MaliciousVersion,
                    description: String::new(),
                    details: FindingDetails::default(),
                })
                .collect(),
            duration_ms: 0,
            degraded,
        }
    }

    #[test]
    fn severity_parses_case_insensitive() {
        assert_eq!("High".parse::<Severity>().unwrap(), Severity::High);
        assert_eq!("CRITICAL".parse::<Severity>().unwrap(), Severity::Critical);
        assert!("bogus".parse::<Severity>().is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn exit_code_legacy_preserves_pre_0_3_0_semantics() {
        // exit_code() is the pre-0.3.0 verdict path preserved verbatim so
        // in-process consumers (crate embedders) see no behavior change on
        // upgrade. It has its own semantics distinct from --fail-on:
        //   0 clean, 1 High+, 2 findings below High (the "found anything?"
        //   signal).
        // v0.3.0 CLI callers get the looser semantic via exit_code_v3.
        assert_eq!(r(vec![Severity::High], false).exit_code(), 1);
        assert_eq!(r(vec![Severity::Medium], false).exit_code(), 2);
        assert_eq!(r(vec![], false).exit_code(), 0);
    }

    #[test]
    fn exit_code_v3_fail_on_high_default_gate() {
        let none = r(vec![], false);
        assert_eq!(none.exit_code_v3(Severity::High, false), 0);
        // Medium is below the fail_on=High threshold — do not block.
        let medium = r(vec![Severity::Medium], false);
        assert_eq!(medium.exit_code_v3(Severity::High, false), 0);
        let high = r(vec![Severity::High], false);
        assert_eq!(high.exit_code_v3(Severity::High, false), 1);
    }

    #[test]
    fn exit_code_v3_fail_on_critical_lets_high_pass() {
        // With --fail-on critical, only Critical blocks; High is now below
        // threshold and exits 0.
        let high = r(vec![Severity::High], false);
        assert_eq!(high.exit_code_v3(Severity::Critical, false), 0);
        let crit = r(vec![Severity::Critical], false);
        assert_eq!(crit.exit_code_v3(Severity::Critical, false), 1);
    }

    #[test]
    fn exit_code_v3_strict_gates_on_degraded_before_findings() {
        let clean_degraded = r(vec![], true);
        assert_eq!(clean_degraded.exit_code_v3(Severity::High, true), 3);
        // strict:false ignores degraded → clean stays clean
        assert_eq!(clean_degraded.exit_code_v3(Severity::High, false), 0);
        // A degraded scan that ALSO found a High under strict still returns
        // 3 — the coverage question dominates the finding gate because we
        // can't know what OTHER findings might exist behind the degraded
        // path.
        let degraded_with_high = r(vec![Severity::High], true);
        assert_eq!(degraded_with_high.exit_code_v3(Severity::High, true), 3);
    }
}
