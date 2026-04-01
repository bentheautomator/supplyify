use anyhow::{Context, Result};
use std::path::Path;

use super::EcosystemParser;
use crate::{Dependency, Ecosystem};

pub struct PipParser;

impl EcosystemParser for PipParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pip
    }

    fn lockfile_names(&self) -> &[&str] {
        &["requirements.txt", "poetry.lock", "Pipfile.lock"]
    }

    fn manifest_names(&self) -> &[&str] {
        &["pyproject.toml"]
    }

    fn parse_lockfile(&self, path: &Path) -> Result<Vec<Dependency>> {
        let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        match filename {
            "requirements.txt" => parse_requirements_txt(path),
            "poetry.lock" => parse_poetry_lock(path),
            "Pipfile.lock" => parse_pipfile_lock(path),
            _ => anyhow::bail!("Unknown pip lockfile: {}", filename),
        }
    }
}

/// Parse requirements.txt (package==version per line)
fn parse_requirements_txt(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let deps = content
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#') && !line.starts_with('-')
        })
        .filter_map(|line| {
            let line = line.trim();
            // Handle: package==version, package>=version, package~=version
            // Also strip inline comments and extras: package[extra]==version ; python_version
            let line = line.split(';').next().unwrap_or(line).trim();
            let line = line.split('#').next().unwrap_or(line).trim();

            // Strip extras: package[extra] -> package
            let pkg_part = if let Some(bracket) = line.find('[') {
                let after_bracket = line[bracket..]
                    .find(']')
                    .map(|i| bracket + i + 1)
                    .unwrap_or(line.len());
                format!("{}{}", &line[..bracket], &line[after_bracket..])
            } else {
                line.to_string()
            };

            // Split on ==, >=, ~=, <=, !=
            for sep in &["==", ">=", "~=", "<=", "!="] {
                if let Some(pos) = pkg_part.find(sep) {
                    let name = pkg_part[..pos].trim().to_lowercase();
                    let version = pkg_part[pos + sep.len()..].trim().to_string();
                    if !name.is_empty() && !version.is_empty() {
                        return Some(Dependency {
                            name,
                            version,
                            ecosystem: Ecosystem::Pip,
                        });
                    }
                }
            }
            None
        })
        .collect();

    Ok(deps)
}

/// Parse poetry.lock (TOML with [[package]] entries)
fn parse_poetry_lock(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    #[derive(serde::Deserialize)]
    struct PoetryLock {
        #[serde(default)]
        package: Vec<PoetryPackage>,
    }

    #[derive(serde::Deserialize)]
    struct PoetryPackage {
        name: String,
        version: String,
    }

    let lock: PoetryLock =
        toml::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))?;

    let deps = lock
        .package
        .into_iter()
        .map(|p| Dependency {
            name: p.name.to_lowercase(),
            version: p.version,
            ecosystem: Ecosystem::Pip,
        })
        .collect();

    Ok(deps)
}

/// Parse Pipfile.lock (JSON)
fn parse_pipfile_lock(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    let mut deps = Vec::new();

    // Check both "default" and "develop" sections
    for section in &["default", "develop"] {
        if let Some(packages) = json.get(section).and_then(|s| s.as_object()) {
            for (name, val) in packages {
                if let Some(version) = val.get("version").and_then(|v| v.as_str()) {
                    let version = version.trim_start_matches("==").to_string();
                    deps.push(Dependency {
                        name: name.to_lowercase(),
                        version,
                        ecosystem: Ecosystem::Pip,
                    });
                }
            }
        }
    }

    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_requirements_txt() {
        let content =
            "# Requirements\nflask==2.3.3\nrequests>=2.31.0\nnumpy==1.25.2  # math\n-r base.txt\n";
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let deps = parse_requirements_txt(tmp.path()).unwrap();
        assert_eq!(deps.len(), 3);
        assert!(deps
            .iter()
            .any(|d| d.name == "flask" && d.version == "2.3.3"));
        assert!(deps
            .iter()
            .any(|d| d.name == "requests" && d.version == "2.31.0"));
    }

    #[test]
    fn test_parse_requirements_with_extras() {
        let content = "uvicorn[standard]==0.24.0\nboto3[crt]==1.34.0\n";
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let deps = parse_requirements_txt(tmp.path()).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "uvicorn" && d.version == "0.24.0"));
    }

    #[test]
    fn test_parse_poetry_lock() {
        let content = r#"
[[package]]
name = "Flask"
version = "2.3.3"

[[package]]
name = "requests"
version = "2.31.0"
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let deps = parse_poetry_lock(tmp.path()).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "flask"));
    }
}
