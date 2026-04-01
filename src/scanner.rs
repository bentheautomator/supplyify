use std::path::Path;
use std::time::Instant;

use crate::ecosystems;
use crate::heuristics;
use crate::indicators::IndicatorDb;
use crate::{Config, Dependency, Ecosystem, Finding, FindingDetails, FindingKind, ScanResult};

/// Scan a single project directory through all 3 layers
pub fn scan(config: &Config, path: &Path) -> ScanResult {
    let start = Instant::now();
    let mut findings = Vec::new();

    // Load indicator database
    let db = match IndicatorDb::load() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Warning: Failed to load indicators: {}", e);
            return ScanResult {
                project_path: path.display().to_string(),
                ecosystems: vec![],
                dep_count: 0,
                findings: vec![],
                duration_ms: start.elapsed().as_millis(),
            };
        }
    };

    // Discover ecosystems and parse dependencies
    let discovered = ecosystems::discover_project(path);
    let ecosystems_found: Vec<Ecosystem> = discovered.iter().map(|(e, _)| *e).collect();
    let all_deps: Vec<&Dependency> = discovered
        .iter()
        .flat_map(|(_, deps)| deps.iter())
        .collect();
    let dep_count = all_deps.len();

    // === Layer 1: Indicator matching (milliseconds) ===
    let version_index = db.version_index();
    let package_index = db.package_index();

    for dep in &all_deps {
        // Check known malicious versions
        if let Some(mv) = version_index.get(&(dep.ecosystem, dep.name.clone(), dep.version.clone()))
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
                    lockfile_path: None,
                },
            });
        }

        // Check known malicious packages
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
                    ..Default::default()
                },
            });
        }

        // Check suspicious ranges
        if let Some(sr) = db.check_range(dep.ecosystem, &dep.name, &dep.version) {
            findings.push(Finding {
                severity: sr.severity,
                package: dep.name.clone(),
                version: dep.version.clone(),
                kind: FindingKind::SuspiciousRange,
                description: sr.description.clone(),
                details: FindingDetails::default(),
            });
        }
    }

    // === Layer 1b: OSV.dev online lookup ===
    if !config.no_osv {
        let osv_findings = crate::osv::query_batch(&all_deps);
        findings.extend(osv_findings);
    }

    // === Layer 2: Heuristics (seconds) ===
    if !config.no_heuristics {
        // Only run npm heuristics if npm ecosystem detected
        if ecosystems_found.contains(&Ecosystem::Npm) {
            findings.extend(heuristics::postinstall::scan(path));
            findings.extend(heuristics::version::scan(&all_deps));
        }
    }

    // Sort findings by severity (critical first)
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    // Dedup: same package+version+kind
    findings.dedup_by(|a, b| {
        a.package == b.package
            && a.version == b.version
            && std::mem::discriminant(&a.kind) == std::mem::discriminant(&b.kind)
    });

    ScanResult {
        project_path: path.display().to_string(),
        ecosystems: ecosystems_found,
        dep_count,
        findings,
        duration_ms: start.elapsed().as_millis(),
    }
}
