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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lockfile_path: Option<String>,
}

/// Result of scanning a single project
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanResult {
    pub project_path: String,
    pub ecosystems: Vec<Ecosystem>,
    pub dep_count: usize,
    pub findings: Vec<Finding>,
    pub duration_ms: u128,
}

impl ScanResult {
    pub fn exit_code(&self) -> i32 {
        if self.findings.iter().any(|f| f.severity >= Severity::High) {
            1
        } else if !self.findings.is_empty() {
            2
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
