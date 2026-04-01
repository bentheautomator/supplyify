use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::{Ecosystem, Severity};

/// Bundled indicators compiled into the binary
const BUNDLED_INDICATORS: &str = include_str!("bundled.toml");

/// Full indicator database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorDb {
    pub meta: IndicatorMeta,
    #[serde(default)]
    pub malicious_version: Vec<MaliciousVersion>,
    #[serde(default)]
    pub malicious_package: Vec<MaliciousPackage>,
    #[serde(default)]
    pub c2_indicator: Vec<C2Indicator>,
    #[serde(default)]
    pub suspicious_range: Vec<SuspiciousRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorMeta {
    pub version: String,
    #[serde(default)]
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousVersion {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: String,
    pub severity: Severity,
    pub description: String,
    #[serde(default)]
    pub c2: Vec<String>,
    #[serde(default)]
    pub cve: String,
    #[serde(default)]
    pub references: Vec<String>,
    pub date: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousPackage {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub severity: Severity,
    pub description: String,
    #[serde(default)]
    pub references: Vec<String>,
    pub date: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Indicator {
    pub address: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub associated_campaigns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousRange {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub range: String,
    pub severity: Severity,
    pub description: String,
}

impl IndicatorDb {
    /// Load the indicator database from all sources
    pub fn load() -> Result<Self> {
        let mut db =
            Self::from_toml(BUNDLED_INDICATORS).context("Failed to parse bundled indicators")?;

        // Try to load user config
        if let Some(user_path) = Self::user_config_path() {
            if user_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&user_path) {
                    if let Ok(user_db) = Self::from_toml(&content) {
                        db.merge(user_db);
                    }
                }
            }
        }

        Ok(db)
    }

    /// Parse from TOML string
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content).context("Failed to parse indicator TOML")
    }

    /// User config path: ~/.config/supplyify/indicators.toml
    pub fn user_config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("supplyify").join("indicators.toml"))
    }

    /// Merge another IndicatorDb into this one (union, dedup by package+version)
    pub fn merge(&mut self, other: IndicatorDb) {
        for mv in other.malicious_version {
            if !self.malicious_version.iter().any(|e| {
                e.package == mv.package && e.version == mv.version && e.ecosystem == mv.ecosystem
            }) {
                self.malicious_version.push(mv);
            }
        }
        for mp in other.malicious_package {
            if !self
                .malicious_package
                .iter()
                .any(|e| e.package == mp.package && e.ecosystem == mp.ecosystem)
            {
                self.malicious_package.push(mp);
            }
        }
        for c2 in other.c2_indicator {
            if !self.c2_indicator.iter().any(|e| e.address == c2.address) {
                self.c2_indicator.push(c2);
            }
        }
        for sr in other.suspicious_range {
            if !self
                .suspicious_range
                .iter()
                .any(|e| e.package == sr.package && e.range == sr.range)
            {
                self.suspicious_range.push(sr);
            }
        }

        self.meta.sources.extend(other.meta.sources);
        self.meta.sources.sort();
        self.meta.sources.dedup();
    }

    /// Check if a specific package@version is known malicious
    pub fn check_version(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        version: &str,
    ) -> Option<&MaliciousVersion> {
        self.malicious_version
            .iter()
            .find(|mv| mv.ecosystem == ecosystem && mv.package == package && mv.version == version)
    }

    /// Check if an entire package is known malicious (any version)
    pub fn check_package(&self, ecosystem: Ecosystem, package: &str) -> Option<&MaliciousPackage> {
        self.malicious_package
            .iter()
            .find(|mp| mp.ecosystem == ecosystem && mp.package == package)
    }

    /// Check if a version falls within a suspicious range
    pub fn check_range(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        version: &str,
    ) -> Option<&SuspiciousRange> {
        self.suspicious_range.iter().find(|sr| {
            sr.ecosystem == ecosystem
                && sr.package == package
                && version_in_range(version, &sr.range)
        })
    }

    /// Build a fast lookup hashmap for version checks
    pub fn version_index(&self) -> HashMap<(Ecosystem, String, String), &MaliciousVersion> {
        self.malicious_version
            .iter()
            .map(|mv| ((mv.ecosystem, mv.package.clone(), mv.version.clone()), mv))
            .collect()
    }

    /// Build a fast lookup hashmap for package checks
    pub fn package_index(&self) -> HashMap<(Ecosystem, String), &MaliciousPackage> {
        self.malicious_package
            .iter()
            .map(|mp| ((mp.ecosystem, mp.package.clone()), mp))
            .collect()
    }
}

/// Simple version range check (supports >=X,<Y format)
fn version_in_range(version: &str, range: &str) -> bool {
    let Ok(ver) = semver::Version::parse(version) else {
        return false;
    };

    for constraint in range.split(',') {
        let constraint = constraint.trim();
        if let Some(bound) = constraint.strip_prefix(">=") {
            if let Ok(bound_ver) = semver::Version::parse(bound) {
                if ver < bound_ver {
                    return false;
                }
            }
        } else if let Some(bound) = constraint.strip_prefix('>') {
            if let Ok(bound_ver) = semver::Version::parse(bound) {
                if ver <= bound_ver {
                    return false;
                }
            }
        } else if let Some(bound) = constraint.strip_prefix("<=") {
            if let Ok(bound_ver) = semver::Version::parse(bound) {
                if ver > bound_ver {
                    return false;
                }
            }
        } else if let Some(bound) = constraint.strip_prefix('<') {
            if let Ok(bound_ver) = semver::Version::parse(bound) {
                if ver >= bound_ver {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_bundled() {
        let db = IndicatorDb::load().unwrap();
        assert!(!db.malicious_version.is_empty());
        assert!(!db.malicious_package.is_empty());
        assert!(!db.c2_indicator.is_empty());
    }

    #[test]
    fn test_check_version() {
        let db = IndicatorDb::load().unwrap();
        let hit = db.check_version(Ecosystem::Npm, "axios", "1.14.1");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_check_package() {
        let db = IndicatorDb::load().unwrap();
        let hit = db.check_package(Ecosystem::Npm, "plain-crypto-js");
        assert!(hit.is_some());
    }

    #[test]
    fn test_check_clean() {
        let db = IndicatorDb::load().unwrap();
        assert!(db
            .check_version(Ecosystem::Npm, "express", "4.18.2")
            .is_none());
        assert!(db.check_package(Ecosystem::Npm, "express").is_none());
    }

    #[test]
    fn test_version_in_range() {
        assert!(version_in_range("0.30.2", ">=0.30.0,<0.30.5"));
        assert!(version_in_range("0.30.0", ">=0.30.0,<0.30.5"));
        assert!(!version_in_range("0.30.5", ">=0.30.0,<0.30.5"));
        assert!(!version_in_range("0.29.0", ">=0.30.0,<0.30.5"));
        assert!(!version_in_range("1.0.0", ">=0.30.0,<0.30.5"));
    }

    #[test]
    fn test_check_range() {
        let db = IndicatorDb::load().unwrap();
        let hit = db.check_range(Ecosystem::Npm, "axios", "0.30.2");
        assert!(hit.is_some());
        assert!(db.check_range(Ecosystem::Npm, "axios", "1.0.0").is_none());
    }
}
