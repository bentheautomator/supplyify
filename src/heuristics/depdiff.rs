//! Dependency-injection heuristic: diff each lockfile against its last
//! committed state (git HEAD) and flag suspicious changes.
//!
//! Supply chain compromises almost always arrive as a *lockfile delta*:
//! a new transitive dependency injected alongside a routine upgrade
//! (axios → plain-crypto-js, March 2026), or a version downgrade pulling
//! a project back into a compromised range. Scanning the lockfile alone
//! sees the absolute state; this layer sees the *change* — which is where
//! the attack is visible.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::ecosystems::{all_parsers, DiscoveredEcosystem};
use crate::versioncmp;
use crate::{Finding, FindingDetails, FindingKind, Severity};

/// Max new packages to name individually in the aggregate finding
const MAX_LISTED: usize = 10;
/// If more new deps than this appeared, it's likely a fresh install or
/// big intentional upgrade — skip flagging to avoid noise.
const NEW_DEP_NOISE_CAP: usize = 25;

pub fn scan(project_path: &Path, discovered: &[DiscoveredEcosystem]) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !is_git_repo(project_path) {
        return findings;
    }

    for d in discovered {
        let Some(lockfile_name) = d.lockfile.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        // Read the lockfile as of HEAD. Absence (new lockfile, untracked
        // file, shallow clone) is normal — skip silently.
        let Some(old_content) = git_show_head(project_path, &d.lockfile) else {
            continue;
        };
        let Some(old_deps) = parse_lockfile_content(lockfile_name, &old_content) else {
            continue;
        };

        // Group versions by package name on both sides. A package legitimately
        // resolves to multiple coexisting versions (very common in Cargo:
        // getrandom 0.2 + 0.4 side by side). Comparing a single "the version"
        // per name produces false downgrades — so we track version SETS and
        // only call something a downgrade when the package has exactly one
        // version on each side and it moved strictly down.
        let mut old: HashMap<&str, Vec<&str>> = HashMap::new();
        for dep in &old_deps {
            old.entry(dep.name.as_str())
                .or_default()
                .push(dep.version.as_str());
        }
        let mut new_by_name: HashMap<&str, Vec<&str>> = HashMap::new();
        for dep in &d.deps {
            new_by_name
                .entry(dep.name.as_str())
                .or_default()
                .push(dep.version.as_str());
        }

        // New packages: names absent from HEAD entirely (a new *version* of an
        // existing package is not an injected dependency).
        let mut new_packages: Vec<&str> = new_by_name
            .keys()
            .filter(|name| !old.contains_key(**name))
            .copied()
            .collect();

        // Downgrades: only unambiguous single-version→single-version moves.
        for (name, new_versions) in &new_by_name {
            let (Some(old_versions), [new_version]) = (old.get(name), new_versions.as_slice())
            else {
                continue;
            };
            let [old_version] = old_versions.as_slice() else {
                continue; // multiple coexisting versions — not a clean downgrade
            };
            if versioncmp::compare(new_version, old_version) == Some(std::cmp::Ordering::Less) {
                findings.push(Finding {
                    severity: Severity::Medium,
                    package: name.to_string(),
                    version: new_version.to_string(),
                    kind: FindingKind::Heuristic("dependency_downgrade".to_string()),
                    description: format!(
                        "Version downgrade since last commit: {} → {}",
                        old_version, new_version
                    ),
                    details: FindingDetails {
                        tags: vec!["heuristic".to_string(), "depdiff".to_string()],
                        lockfile_path: Some(d.lockfile.display().to_string()),
                        remediation: Some(format!(
                            "Verify the downgrade of {} from {} to {} was intentional. \
                             Downgrade attacks reintroduce patched vulnerabilities.",
                            name, old_version, new_version
                        )),
                        ..Default::default()
                    },
                });
            }
        }

        new_packages.sort_unstable();
        let count = new_packages.len();
        if count > 0 && count <= NEW_DEP_NOISE_CAP {
            let listed: Vec<&str> = new_packages.iter().take(MAX_LISTED).copied().collect();
            let suffix = if count > MAX_LISTED {
                format!(" (+{} more)", count - MAX_LISTED)
            } else {
                String::new()
            };
            findings.push(Finding {
                severity: Severity::Low,
                package: format!("{} ({})", lockfile_name, d.ecosystem),
                version: String::new(),
                kind: FindingKind::Heuristic("new_dependencies".to_string()),
                description: format!(
                    "{} new dependenc{} since last commit: {}{}",
                    count,
                    if count == 1 { "y" } else { "ies" },
                    listed.join(", "),
                    suffix
                ),
                details: FindingDetails {
                    tags: vec!["heuristic".to_string(), "depdiff".to_string()],
                    lockfile_path: Some(d.lockfile.display().to_string()),
                    remediation: Some(
                        "Review each new dependency before committing. Injected transitive \
                         dependencies are the primary delivery mechanism for supply chain \
                         attacks — verify these arrived from an upgrade you intended."
                            .to_string(),
                    ),
                    ..Default::default()
                },
            });
        }
    }

    findings
}

fn is_git_repo(path: &Path) -> bool {
    Command::new("git")
        .args(["-C"])
        .arg(path)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// `git show HEAD:<relpath>` for the lockfile. None if not tracked at HEAD.
fn git_show_head(project_path: &Path, lockfile: &Path) -> Option<String> {
    let rel = lockfile.strip_prefix(project_path).ok()?;
    // git show wants forward slashes relative to the repo the -C points at
    let spec = format!("HEAD:./{}", rel.to_string_lossy().replace('\\', "/"));
    let out = Command::new("git")
        .args(["-C"])
        .arg(project_path)
        .args(["show", &spec])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// Parse lockfile content via the regular parsers. Parsers take paths, so
/// stage the old content under the same filename in a *unique* temp dir
/// (the filename drives format dispatch). A unique dir per call is
/// required — parallel scans (rayon sweep, parallel tests) would
/// otherwise race on a shared path.
fn parse_lockfile_content(lockfile_name: &str, content: &str) -> Option<Vec<crate::Dependency>> {
    let dir = tempfile::tempdir().ok()?;
    let tmp_path = dir.path().join(lockfile_name);
    std::fs::write(&tmp_path, content).ok()?;

    all_parsers()
        .iter()
        .find(|p| p.lockfile_names().contains(&lockfile_name))
        .and_then(|p| p.parse_lockfile(&tmp_path).ok())
    // dir (and the staged file) are removed when `dir` drops
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ecosystem;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(ok, "git {:?} failed in {:?}", args, dir);
    }

    fn lockfile_json(entries: &[(&str, &str)]) -> String {
        let packages: Vec<String> = entries
            .iter()
            .map(|(n, v)| format!(r#""node_modules/{}": {{ "version": "{}" }}"#, n, v))
            .collect();
        format!(
            r#"{{"lockfileVersion": 3, "packages": {{ "": {{"name":"t","version":"1.0.0"}}, {} }}}}"#,
            packages.join(",")
        )
    }

    fn setup_repo(old: &str, new: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        git(p, &["init", "-q"]);
        git(p, &["config", "user.email", "t@t"]);
        git(p, &["config", "user.name", "t"]);
        // CI/sandbox environments may force commit signing globally
        git(p, &["config", "commit.gpgsign", "false"]);
        std::fs::write(p.join("package-lock.json"), old).unwrap();
        git(p, &["add", "."]);
        git(p, &["commit", "-q", "-m", "old lockfile"]);
        std::fs::write(p.join("package-lock.json"), new).unwrap();
        dir
    }

    fn discover(dir: &Path) -> Vec<DiscoveredEcosystem> {
        crate::ecosystems::discover_project(dir).ecosystems
    }

    #[test]
    fn flags_injected_dependency() {
        // The March 2026 axios pattern: upgrade brings a new transitive dep
        let old = lockfile_json(&[("axios", "1.14.0")]);
        let new = lockfile_json(&[("axios", "1.14.1"), ("plain-crypto-js", "4.2.1")]);
        let repo = setup_repo(&old, &new);

        let findings = scan(repo.path(), &discover(repo.path()));
        let inj: Vec<_> = findings
            .iter()
            .filter(|f| f.kind.name() == "new_dependencies")
            .collect();
        assert_eq!(inj.len(), 1);
        assert!(inj[0].description.contains("plain-crypto-js"));
    }

    #[test]
    fn flags_downgrade() {
        let old = lockfile_json(&[("lodash", "4.17.21")]);
        let new = lockfile_json(&[("lodash", "4.17.10")]);
        let repo = setup_repo(&old, &new);

        let findings = scan(repo.path(), &discover(repo.path()));
        let down: Vec<_> = findings
            .iter()
            .filter(|f| f.kind.name() == "dependency_downgrade")
            .collect();
        assert_eq!(down.len(), 1);
        assert_eq!(down[0].package, "lodash");
        assert_eq!(down[0].severity, Severity::Medium);
    }

    #[test]
    fn multiple_coexisting_versions_are_not_downgrades() {
        // Cargo routinely resolves several majors of one crate side by side.
        // HEAD has getrandom 0.4.2; new lockfile adds 0.2.17 ALONGSIDE it
        // (0.4.2 still present, nested under another dep). That's not a
        // downgrade — both coexist. Distinct lockfile paths, same package name.
        let old = r#"{"lockfileVersion":3,"packages":{
            "":{"name":"t","version":"1.0.0"},
            "node_modules/getrandom":{"version":"0.4.2"}
        }}"#
        .to_string();
        let new = r#"{"lockfileVersion":3,"packages":{
            "":{"name":"t","version":"1.0.0"},
            "node_modules/getrandom":{"version":"0.4.2"},
            "node_modules/legacy-dep/node_modules/getrandom":{"version":"0.2.17"}
        }}"#
        .to_string();
        let repo = setup_repo(&old, &new);

        let findings = scan(repo.path(), &discover(repo.path()));
        assert!(
            findings
                .iter()
                .all(|f| f.kind.name() != "dependency_downgrade"),
            "coexisting versions must not be flagged as a downgrade: {:?}",
            findings
        );
    }

    #[test]
    fn clean_when_unchanged() {
        let content = lockfile_json(&[("axios", "1.14.0")]);
        let repo = setup_repo(&content, &content);
        assert!(scan(repo.path(), &discover(repo.path())).is_empty());
    }

    #[test]
    fn silent_outside_git() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            lockfile_json(&[("axios", "1.14.0")]),
        )
        .unwrap();
        assert!(scan(dir.path(), &discover(dir.path())).is_empty());
    }

    #[test]
    fn upgrades_are_not_flagged() {
        let old = lockfile_json(&[("axios", "1.14.0")]);
        let new = lockfile_json(&[("axios", "1.15.0")]);
        let repo = setup_repo(&old, &new);
        assert!(scan(repo.path(), &discover(repo.path())).is_empty());
    }

    #[test]
    fn parses_old_content_by_filename() {
        let deps =
            parse_lockfile_content("package-lock.json", &lockfile_json(&[("axios", "1.0.0")]))
                .unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, Ecosystem::Npm);
    }
}
