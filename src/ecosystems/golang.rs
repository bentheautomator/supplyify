use anyhow::{Context, Result};
use std::path::Path;

use super::EcosystemParser;
use crate::{Dependency, Ecosystem};

pub struct GoParser;

impl EcosystemParser for GoParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }

    fn lockfile_names(&self) -> &[&str] {
        &["go.sum"]
    }

    fn manifest_names(&self) -> &[&str] {
        &["go.mod"]
    }

    fn parse_lockfile(&self, path: &Path) -> Result<Vec<Dependency>> {
        parse_go_sum(path)
    }
}

/// Parse go.sum. Each line is `module version hash`; every module appears
/// twice (`v1.2.3` and `v1.2.3/go.mod`). go.sum can also retain entries
/// for versions no longer in go.mod — scanning all of them is intentional:
/// anything in go.sum was fetched at some point.
fn parse_go_sum(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut deps: Vec<Dependency> = content
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let module = parts.next()?;
            let version = parts.next()?;
            // Skip the /go.mod companion entries
            let version = version.strip_suffix("/go.mod").unwrap_or(version);
            // OSV's Go ecosystem uses versions without the leading 'v'
            let version = version.strip_prefix('v').unwrap_or(version);
            if module.is_empty() || version.is_empty() {
                return None;
            }
            Some(Dependency {
                name: module.to_string(),
                version: version.to_string(),
                ecosystem: Ecosystem::Go,
            })
        })
        .collect();

    deps.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    deps.dedup_by(|a, b| a.name == b.name && a.version == b.version);

    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_go_sum() {
        let content = "\
github.com/stretchr/testify v1.8.4 h1:CcVxjf/Q8H0+ZLBfQ=
github.com/stretchr/testify v1.8.4/go.mod h1:abc123=
golang.org/x/crypto v0.17.0 h1:def456=
golang.org/x/crypto v0.17.0/go.mod h1:ghi789=
";
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let deps = parse_go_sum(tmp.path()).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "github.com/stretchr/testify" && d.version == "1.8.4"));
        assert!(deps
            .iter()
            .any(|d| d.name == "golang.org/x/crypto" && d.version == "0.17.0"));
    }

    #[test]
    fn test_parse_go_sum_multiple_versions_kept() {
        // Stale versions in go.sum were still fetched — scan them all
        let content = "\
github.com/foo/bar v1.0.0 h1:aaa=
github.com/foo/bar v1.0.0/go.mod h1:bbb=
github.com/foo/bar v1.1.0 h1:ccc=
github.com/foo/bar v1.1.0/go.mod h1:ddd=
";
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let deps = parse_go_sum(tmp.path()).unwrap();
        assert_eq!(deps.len(), 2);
    }
}
