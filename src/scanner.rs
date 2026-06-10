use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use crate::ecosystems;
use crate::heuristics;
use crate::indicators::IndicatorDb;
use crate::plugin::{PluginContext, PluginRegistry};
use crate::policy::Policy;
use crate::{
    Dependency, Ecosystem, Finding, FindingDetails, FindingKind, ScanOptions, ScanResult, Severity,
};

/// Scan a single project directory through all detection layers.
pub fn scan(opts: &ScanOptions, path: &Path) -> ScanResult {
    scan_with_plugins(opts, path, &PluginRegistry::new())
}

/// Scan with an explicit plugin registry (enterprise builds register
/// indicator-source / policy-engine plugins here).
pub fn scan_with_plugins(opts: &ScanOptions, path: &Path, plugins: &PluginRegistry) -> ScanResult {
    let start = Instant::now();
    let mut findings = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut degraded = false;

    // Load indicator database. Failure degrades the scan but does NOT
    // abort it — OSV and heuristics can still run.
    let db = match IndicatorDb::load() {
        Ok(db) => {
            warnings.extend(db.validate());
            Some(db)
        }
        Err(e) => {
            warnings.push(format!(
                "indicator database failed to load: {} — Layer 1a skipped",
                e
            ));
            degraded = true;
            None
        }
    };

    // Discover ecosystems and parse dependencies
    let discovery = ecosystems::discover_project(path);
    if !discovery.warnings.is_empty() {
        degraded = true;
        warnings.extend(discovery.warnings);
    }
    let ecosystems_found: Vec<Ecosystem> =
        discovery.ecosystems.iter().map(|d| d.ecosystem).collect();
    let all_deps: Vec<&Dependency> = discovery
        .ecosystems
        .iter()
        .flat_map(|d| d.deps.iter())
        .collect();
    let dep_count = all_deps.len();

    // === Layer 1a: Indicator matching (offline, milliseconds) ===
    if let Some(ref db) = db {
        let version_index = db.version_index();
        let package_index = db.package_index();

        for d in &discovery.ecosystems {
            let lockfile = d.lockfile.display().to_string();
            for dep in &d.deps {
                if let Some(mv) =
                    version_index.get(&(dep.ecosystem, dep.name.clone(), dep.version.clone()))
                {
                    findings.push(Finding {
                        severity: mv.severity,
                        package: dep.name.clone(),
                        version: dep.version.clone(),
                        kind: FindingKind::MaliciousVersion,
                        description: mv.description.clone(),
                        details: FindingDetails {
                            c2: mv.c2.clone(),
                            cve: if mv.cve.is_empty() {
                                None
                            } else {
                                Some(mv.cve.clone())
                            },
                            references: mv.references.clone(),
                            tags: mv.tags.clone(),
                            advisory_url: mv.references.first().cloned(),
                            lockfile_path: Some(lockfile.clone()),
                            remediation: Some(format!(
                                "IMMEDIATELY remove {}@{}. This is a confirmed malicious version. \
                                 Rotate any secrets or credentials on affected machines.",
                                dep.name, dep.version
                            )),
                            ..Default::default()
                        },
                    });
                }

                if let Some(mp) = package_index.get(&(dep.ecosystem, dep.name.clone())) {
                    findings.push(Finding {
                        severity: mp.severity,
                        package: dep.name.clone(),
                        version: dep.version.clone(),
                        kind: FindingKind::MaliciousPackage,
                        description: mp.description.clone(),
                        details: FindingDetails {
                            references: mp.references.clone(),
                            tags: mp.tags.clone(),
                            advisory_url: mp.references.first().cloned(),
                            lockfile_path: Some(lockfile.clone()),
                            remediation: Some(format!(
                                "IMMEDIATELY remove {}. This entire package is malicious. \
                                 Run: npm uninstall {} / cargo rm {} / pip uninstall {}",
                                dep.name, dep.name, dep.name, dep.name
                            )),
                            ..Default::default()
                        },
                    });
                }

                if let Some(sr) = db.check_range(dep.ecosystem, &dep.name, &dep.version) {
                    findings.push(Finding {
                        severity: sr.severity,
                        package: dep.name.clone(),
                        version: dep.version.clone(),
                        kind: FindingKind::SuspiciousRange,
                        description: sr.description.clone(),
                        details: FindingDetails {
                            lockfile_path: Some(lockfile.clone()),
                            remediation: Some(format!(
                                "Upgrade {} to a version outside the suspicious range. \
                                 This version was published during a known compromise window.",
                                dep.name
                            )),
                            ..Default::default()
                        },
                    });
                }
            }
        }
    }

    // === Layer 1b: OSV.dev online lookup ===
    if opts.osv {
        let outcome = crate::osv::query_batch(&all_deps);
        findings.extend(outcome.findings);
        if !outcome.warnings.is_empty() {
            degraded = true;
            warnings.extend(outcome.warnings);
        }
    }

    // === Plugins: indicator sources + policy engines (enterprise) ===
    let owned_deps: Vec<Dependency> = all_deps.iter().map(|d| (*d).clone()).collect();
    let ctx = PluginContext {
        opts,
        project_path: path,
        dependencies: &owned_deps,
    };
    findings.extend(plugins.check_all_indicators(&ctx, &all_deps));
    findings.extend(plugins.evaluate_all_policies(&ctx, &all_deps));

    // === Layer 2: Heuristics (offline) ===
    if opts.heuristics {
        let c2_addresses: Vec<String> = db
            .as_ref()
            .map(|db| db.c2_indicator.iter().map(|c| c.address.clone()).collect())
            .unwrap_or_default();

        if ecosystems_found.contains(&Ecosystem::Npm) {
            findings.extend(heuristics::postinstall::scan(path, &c2_addresses));
            findings.extend(heuristics::version::scan(&all_deps));
        }
        // Dependency-injection heuristic: lockfile diff vs git HEAD
        findings.extend(heuristics::depdiff::scan(path, &discovery.ecosystems));

        // Targeted deep scans on packages flagged High+ by earlier layers
        let flagged = flagged_packages(&findings);
        if !flagged.is_empty() {
            findings.extend(heuristics::obfuscation::scan_flagged(
                path,
                &flagged,
                &c2_addresses,
            ));

            // === Layer 3: codemap deep analysis (skipped if not installed) ===
            if opts.codemap {
                findings.extend(crate::codemap::scan_flagged(path, &flagged));
            }
        }
    }

    // === Project policy: .supplyify.toml ignore rules ===
    let (policy, policy_warnings) = Policy::load(path);
    warnings.extend(policy_warnings);
    let (mut findings, ignored_count) = policy.apply(findings);

    // Dedup on (package, version, kind name), keeping the highest-severity
    // instance. NOTE: Vec::dedup_by only removes ADJACENT duplicates and
    // discriminant() collapsed all Heuristic kinds — both caused real
    // dupes/drops before. Sort groups duplicates first, keep-first wins.
    findings.sort_by(|a, b| {
        (
            &a.package,
            &a.version,
            a.kind.name(),
            std::cmp::Reverse(a.severity),
        )
            .cmp(&(
                &b.package,
                &b.version,
                b.kind.name(),
                std::cmp::Reverse(b.severity),
            ))
    });
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    findings.retain(|f| {
        seen.insert((
            f.package.clone(),
            f.version.clone(),
            f.kind.name().to_string(),
        ))
    });

    // Display order: critical first
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let result = ScanResult {
        project_path: path.display().to_string(),
        ecosystems: ecosystems_found,
        dep_count,
        findings,
        duration_ms: start.elapsed().as_millis(),
        warnings,
        degraded,
        ignored_count,
    };

    plugins.run_post_scan(&ctx, std::slice::from_ref(&result));

    result
}

/// Packages flagged High or Critical by base layers — candidates for the
/// targeted obfuscation and codemap layers.
fn flagged_packages(findings: &[Finding]) -> Vec<String> {
    let mut flagged: Vec<String> = findings
        .iter()
        .filter(|f| f.severity >= Severity::High && !f.package.is_empty())
        .map(|f| f.package.clone())
        .collect();
    flagged.sort_unstable();
    flagged.dedup();
    flagged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offline_opts() -> ScanOptions {
        ScanOptions {
            osv: false,
            heuristics: true,
            codemap: false,
            strict: false,
            fail_on: Severity::High,
        }
    }

    fn write_lockfile(dir: &Path, entries: &[(&str, &str)]) {
        let packages: Vec<String> = entries
            .iter()
            .map(|(n, v)| format!(r#""node_modules/{}": {{ "version": "{}" }}"#, n, v))
            .collect();
        let json = format!(
            r#"{{"lockfileVersion": 3, "packages": {{ "": {{"name":"t","version":"1.0.0"}}, {} }}}}"#,
            packages.join(",")
        );
        std::fs::write(dir.join("package-lock.json"), json).unwrap();
    }

    #[test]
    fn detects_bundled_indicator() {
        let dir = tempfile::tempdir().unwrap();
        write_lockfile(dir.path(), &[("axios", "1.14.1"), ("express", "4.18.2")]);

        let result = scan(&offline_opts(), dir.path());
        assert!(result
            .findings
            .iter()
            .any(|f| f.package == "axios" && f.severity == Severity::Critical));
        // lockfile_path now populated on indicator findings
        let axios = result
            .findings
            .iter()
            .find(|f| f.package == "axios")
            .unwrap();
        assert!(axios.details.lockfile_path.is_some());
        assert_eq!(result.exit_code(&offline_opts()), 1);
    }

    #[test]
    fn clean_project_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        write_lockfile(dir.path(), &[("express", "4.18.2")]);

        let result = scan(&offline_opts(), dir.path());
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        assert!(!result.degraded);
        assert_eq!(result.exit_code(&offline_opts()), 0);
    }

    #[test]
    fn duplicate_findings_collapse_to_highest_severity() {
        // axios 1.14.1 hits malicious_version; craft a near-duplicate via
        // dedup directly: two same-key findings, different severity
        let mut findings = vec![
            Finding {
                severity: Severity::Medium,
                package: "p".into(),
                version: "1".into(),
                kind: FindingKind::MaliciousPackage,
                description: "low copy".into(),
                details: FindingDetails::default(),
            },
            Finding {
                severity: Severity::Critical,
                package: "p".into(),
                version: "1".into(),
                kind: FindingKind::MaliciousPackage,
                description: "high copy".into(),
                details: FindingDetails::default(),
            },
            // Different heuristic kinds must NOT collapse (discriminant bug)
            Finding {
                severity: Severity::Medium,
                package: "p".into(),
                version: "1".into(),
                kind: FindingKind::Heuristic("postinstall".into()),
                description: "h1".into(),
                details: FindingDetails::default(),
            },
            Finding {
                severity: Severity::Medium,
                package: "p".into(),
                version: "1".into(),
                kind: FindingKind::Heuristic("version_anomaly".into()),
                description: "h2".into(),
                details: FindingDetails::default(),
            },
        ];
        findings.sort_by(|a, b| {
            (
                &a.package,
                &a.version,
                a.kind.name(),
                std::cmp::Reverse(a.severity),
            )
                .cmp(&(
                    &b.package,
                    &b.version,
                    b.kind.name(),
                    std::cmp::Reverse(b.severity),
                ))
        });
        let mut seen = HashSet::new();
        findings.retain(|f| {
            seen.insert((
                f.package.clone(),
                f.version.clone(),
                f.kind.name().to_string(),
            ))
        });

        assert_eq!(findings.len(), 3);
        let kept = findings
            .iter()
            .find(|f| matches!(f.kind, FindingKind::MaliciousPackage))
            .unwrap();
        assert_eq!(
            kept.severity,
            Severity::Critical,
            "must keep the worst copy"
        );
    }

    #[test]
    fn policy_file_suppresses_findings() {
        let dir = tempfile::tempdir().unwrap();
        write_lockfile(dir.path(), &[("axios", "1.14.1")]);
        std::fs::write(
            dir.path().join(".supplyify.toml"),
            r#"
[[ignore]]
package = "axios"
version = "1.14.1"
reason = "test suppression"
"#,
        )
        .unwrap();

        let result = scan(&offline_opts(), dir.path());
        assert!(result.findings.iter().all(|f| f.package != "axios"));
        assert!(result.ignored_count >= 1);
    }

    #[test]
    fn unparseable_lockfile_degrades_scan() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "not [ valid { toml").unwrap();

        let result = scan(&offline_opts(), dir.path());
        assert!(result.degraded, "parse failure must degrade the scan");
        assert!(!result.warnings.is_empty());
        // Default mode: degraded-but-clean passes
        assert_eq!(result.exit_code(&offline_opts()), 0);
        // Strict mode: exit 3
        let strict = ScanOptions {
            strict: true,
            ..offline_opts()
        };
        assert_eq!(result.exit_code(&strict), 3);
    }
}
