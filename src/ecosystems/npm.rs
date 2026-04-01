use anyhow::{Context, Result};
use std::path::Path;

use super::EcosystemParser;
use crate::{Dependency, Ecosystem};

pub struct NpmParser;

impl EcosystemParser for NpmParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn lockfile_names(&self) -> &[&str] {
        &["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    }

    fn manifest_names(&self) -> &[&str] {
        &["package.json"]
    }

    fn parse_lockfile(&self, path: &Path) -> Result<Vec<Dependency>> {
        let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");

        match filename {
            "package-lock.json" => parse_package_lock(path),
            "yarn.lock" => parse_yarn_lock(path),
            "pnpm-lock.yaml" => parse_pnpm_lock(path),
            _ => anyhow::bail!("Unknown npm lockfile: {}", filename),
        }
    }
}

/// Parse package-lock.json (npm v2/v3 format with nested "packages")
fn parse_package_lock(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    let mut deps = Vec::new();

    // npm v2/v3: "packages" field with nested entries
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        for (key, val) in packages {
            // Skip the root package (empty key)
            if key.is_empty() {
                continue;
            }
            // Key is like "node_modules/axios" or "node_modules/@scope/pkg"
            let name = key
                .strip_prefix("node_modules/")
                .unwrap_or(key)
                // Handle nested: node_modules/foo/node_modules/bar -> bar
                .rsplit("node_modules/")
                .next()
                .unwrap_or(key);

            if let Some(version) = val.get("version").and_then(|v| v.as_str()) {
                deps.push(Dependency {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: Ecosystem::Npm,
                });
            }
        }
    }
    // npm v1 fallback: "dependencies" field
    else if let Some(dependencies) = json.get("dependencies").and_then(|d| d.as_object()) {
        collect_npm_v1_deps(dependencies, &mut deps);
    }

    Ok(deps)
}

/// Recursively collect deps from npm v1 lockfile format
fn collect_npm_v1_deps(
    obj: &serde_json::Map<String, serde_json::Value>,
    deps: &mut Vec<Dependency>,
) {
    for (name, val) in obj {
        if let Some(version) = val.get("version").and_then(|v| v.as_str()) {
            deps.push(Dependency {
                name: name.clone(),
                version: version.to_string(),
                ecosystem: Ecosystem::Npm,
            });
        }
        // Recurse into nested dependencies
        if let Some(nested) = val.get("dependencies").and_then(|d| d.as_object()) {
            collect_npm_v1_deps(nested, deps);
        }
    }
}

/// Parse yarn.lock (custom format)
fn parse_yarn_lock(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut deps = Vec::new();
    let mut current_name = String::new();

    for line in content.lines() {
        // Package headers: "axios@^1.6.0, axios@^1.7.0:" or "@scope/pkg@^1.0.0:"
        if !line.starts_with(' ')
            && !line.starts_with('#')
            && line.contains('@')
            && line.ends_with(':')
        {
            // Extract package name from first entry
            let entry = line.trim_end_matches(':').split(',').next().unwrap_or("");
            let entry = entry.trim().trim_matches('"');
            // Find the last @ that separates name from version spec
            if let Some(at_pos) = entry.rfind('@') {
                if at_pos > 0 {
                    current_name = entry[..at_pos].to_string();
                }
            }
        }
        // Version line: "  version "1.7.2""
        else if line.starts_with("  version ") && !current_name.is_empty() {
            let version = line
                .trim()
                .strip_prefix("version ")
                .unwrap_or("")
                .trim_matches('"');
            if !version.is_empty() {
                deps.push(Dependency {
                    name: current_name.clone(),
                    version: version.to_string(),
                    ecosystem: Ecosystem::Npm,
                });
            }
        }
    }

    // Dedup (yarn.lock can list same package@version multiple times)
    deps.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    deps.dedup_by(|a, b| a.name == b.name && a.version == b.version);

    Ok(deps)
}

/// Parse pnpm-lock.yaml
fn parse_pnpm_lock(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    let mut deps = Vec::new();

    // pnpm v6+: "packages" map with keys like "/axios@1.7.2"
    if let Some(packages) = yaml.get("packages").and_then(|p| p.as_mapping()) {
        for (key, _val) in packages {
            if let Some(key_str) = key.as_str() {
                // Format: "/package@version" or "/@scope/package@version"
                let key_str = key_str.trim_start_matches('/');
                if let Some(at_pos) = key_str.rfind('@') {
                    if at_pos > 0 {
                        let name = &key_str[..at_pos];
                        let version = &key_str[at_pos + 1..];
                        deps.push(Dependency {
                            name: name.to_string(),
                            version: version.to_string(),
                            ecosystem: Ecosystem::Npm,
                        });
                    }
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
    fn test_parse_package_lock_v2() {
        let json = r#"{
            "name": "test-project",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "test-project", "version": "1.0.0" },
                "node_modules/axios": { "version": "1.14.1" },
                "node_modules/express": { "version": "4.18.2" },
                "node_modules/plain-crypto-js": { "version": "4.2.1" }
            }
        }"#;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), json).unwrap();

        let deps = parse_package_lock(tmp.path()).unwrap();
        assert_eq!(deps.len(), 3);
        assert!(deps
            .iter()
            .any(|d| d.name == "axios" && d.version == "1.14.1"));
        assert!(deps.iter().any(|d| d.name == "plain-crypto-js"));
    }

    #[test]
    fn test_parse_yarn_lock() {
        let content = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.

axios@^1.6.0:
  version "1.14.1"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz"
  integrity sha512-abc123

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
"#;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let deps = parse_yarn_lock(tmp.path()).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "axios" && d.version == "1.14.1"));
    }
}
