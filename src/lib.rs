pub mod codemap;
pub mod ecosystems;
pub mod heuristics;
pub mod indicators;
pub mod osv;
pub mod output;
pub mod plugin;
pub mod policy;
pub mod scanner;
pub mod sweep;
pub mod versioncmp;

/// Output format for results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Agent,
    Sarif,
}

/// Detection options — what the scanner runs. Pure library concern:
/// no presentation fields, no process exit. Hosts (CLI, gitguard,
/// codemap) build one of these and interpret the ScanResult themselves.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Query OSV.dev online (Layer 1b)
    pub osv: bool,
    /// Run offline heuristics (Layer 2)
    pub heuristics: bool,
    /// Deep-analyze flagged packages with the codemap binary (Layer 3)
    pub codemap: bool,
    /// Fail closed: a degraded scan (OSV unreachable, unparseable
    /// lockfile, bad indicator DB) is an error, not a silent pass
    pub strict: bool,
    /// Minimum severity that produces exit code 1
    pub fail_on: Severity,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            osv: true,
            heuristics: true,
            codemap: true,
            strict: false,
            fail_on: Severity::High,
        }
    }
}

/// CLI-facing configuration: presentation + detection options
#[derive(Clone)]
pub struct Config {
    pub format: OutputFormat,
    pub output: Option<String>,
    pub quiet: bool,
    pub scan: ScanOptions,
}

impl Config {
    /// True for the colorized terminal format — i.e. not a
    /// machine-readable format (json/agent/sarif) that prints its own
    /// structured payload at the end.
    pub fn is_human(&self) -> bool {
        self.format == OutputFormat::Text
    }
}

/// Severity levels for findings
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
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

impl FindingKind {
    /// Stable machine name — used for dedup keys, agent output, SARIF
    /// rule IDs, and `.supplyify.toml` ignore rules.
    pub fn name(&self) -> &str {
        match self {
            FindingKind::MaliciousVersion => "malicious_version",
            FindingKind::MaliciousPackage => "malicious_package",
            FindingKind::SuspiciousRange => "suspicious_range",
            FindingKind::Heuristic(h) => h.as_str(),
        }
    }
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
    /// Non-fatal problems encountered during the scan. A non-empty list
    /// means coverage was reduced — "clean" cannot be fully trusted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// True when any detection layer could not complete (OSV unreachable,
    /// indicator DB unloadable, lockfile unparseable, ...)
    pub degraded: bool,
    /// Findings suppressed by `.supplyify.toml` ignore rules
    pub ignored_count: usize,
}

/// Human-readable duration: ms → s → m. Shared by single-scan and sweep
/// summaries so the two never drift.
pub fn format_duration_ms(ms: u128) -> String {
    if ms >= 60_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else if ms >= 1_000 {
        format!("{:.1}s", ms as f64 / 1_000.0)
    } else {
        format!("{}ms", ms)
    }
}

/// The host portion of a C2 `address` (`host` or `host:port`). Stripping
/// the port lets a `host:port` indicator match a bare-host reference in
/// source. Shared by the postinstall and obfuscation heuristics.
pub fn c2_host(address: &str) -> &str {
    address.split(':').next().unwrap_or(address)
}

impl ScanResult {
    pub fn duration_display(&self) -> String {
        format_duration_ms(self.duration_ms)
    }

    /// Exit code policy:
    /// 0 = clean, 1 = findings at/above `fail_on`, 2 = findings below
    /// `fail_on`, 3 = strict mode and the scan was degraded ("we could
    /// not fully check" is NOT the same as "clean").
    pub fn exit_code(&self, opts: &ScanOptions) -> i32 {
        if self.findings.iter().any(|f| f.severity >= opts.fail_on) {
            1
        } else if !self.findings.is_empty() {
            2
        } else if opts.strict && self.degraded {
            3
        } else {
            0
        }
    }

    pub fn count_by_severity(&self) -> (usize, usize, usize, usize) {
        let mut counts = (0, 0, 0, 0);
        for f in &self.findings {
            match f.severity {
                Severity::Critical => counts.0 += 1,
                Severity::High => counts.1 += 1,
                Severity::Medium => counts.2 += 1,
                Severity::Low => counts.3 += 1,
            }
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result_with(findings: Vec<Finding>, degraded: bool) -> ScanResult {
        ScanResult {
            project_path: ".".into(),
            ecosystems: vec![],
            dep_count: 0,
            findings,
            duration_ms: 0,
            warnings: vec![],
            degraded,
            ignored_count: 0,
        }
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            severity,
            package: "pkg".into(),
            version: "1.0.0".into(),
            kind: FindingKind::MaliciousVersion,
            description: "test".into(),
            details: FindingDetails::default(),
        }
    }

    #[test]
    fn exit_code_clean() {
        let opts = ScanOptions::default();
        assert_eq!(result_with(vec![], false).exit_code(&opts), 0);
    }

    #[test]
    fn exit_code_fail_on_threshold() {
        let mut opts = ScanOptions::default();
        let high = result_with(vec![finding(Severity::High)], false);
        assert_eq!(high.exit_code(&opts), 1);
        // Raising the threshold demotes High to a warning
        opts.fail_on = Severity::Critical;
        assert_eq!(high.exit_code(&opts), 2);
        // Lowering it promotes Low to a failure
        opts.fail_on = Severity::Low;
        let low = result_with(vec![finding(Severity::Low)], false);
        assert_eq!(low.exit_code(&opts), 1);
    }

    #[test]
    fn exit_code_strict_degraded() {
        let mut opts = ScanOptions::default();
        let degraded = result_with(vec![], true);
        // Default: degraded-but-clean passes (with warnings surfaced)
        assert_eq!(degraded.exit_code(&opts), 0);
        // Strict: degraded-but-clean is exit 3 — fail closed
        opts.strict = true;
        assert_eq!(degraded.exit_code(&opts), 3);
        // Findings still take precedence over degradation
        let both = result_with(vec![finding(Severity::Critical)], true);
        assert_eq!(both.exit_code(&opts), 1);
    }
}
