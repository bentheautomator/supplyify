use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

use super::EcosystemParser;
use crate::{Dependency, Ecosystem};

pub struct CargoParser;

impl EcosystemParser for CargoParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn lockfile_names(&self) -> &[&str] {
        &["Cargo.lock"]
    }

    fn manifest_names(&self) -> &[&str] {
        &["Cargo.toml"]
    }

    fn parse_lockfile(&self, path: &Path) -> Result<Vec<Dependency>> {
        parse_cargo_lock(path)
    }
}

#[derive(Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

fn parse_cargo_lock(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let lock: CargoLock =
        toml::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))?;

    let deps = lock
        .package
        .into_iter()
        // Only include registry packages (skip path dependencies)
        .filter(|p| {
            p.source
                .as_ref()
                .map(|s| s.starts_with("registry+"))
                .unwrap_or(false)
        })
        .map(|p| Dependency {
            name: p.name,
            version: p.version,
            ecosystem: Ecosystem::Cargo,
        })
        .collect();

    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cargo_lock() {
        let content = r#"
[[package]]
name = "my-project"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "anyhow"
version = "1.0.86"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-dep"
version = "0.1.0"
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let deps = parse_cargo_lock(tmp.path()).unwrap();
        // Should exclude root project and path deps
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "serde"));
        assert!(deps.iter().any(|d| d.name == "anyhow"));
        assert!(!deps.iter().any(|d| d.name == "local-dep"));
    }

    #[test]
    fn test_parse_real_cargo_lock() {
        // Parse this repo's own Cargo.lock
        let repo_root = env!("CARGO_MANIFEST_DIR");
        let lock_path = std::path::Path::new(repo_root).join("../Cargo.lock");
        if lock_path.exists() {
            let deps = parse_cargo_lock(&lock_path).unwrap();
            assert!(deps.len() > 50, "Should have many deps, got {}", deps.len());
        }
    }
}
