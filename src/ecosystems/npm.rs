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

            // Aliased installs (`npm i alias@npm:real-pkg@1.0.0`) carry the
            // real package name in a "name" field — match indicators against
            // the real package, not the alias.
            let name = val.get("name").and_then(|n| n.as_str()).unwrap_or(name);

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

/// Parse yarn.lock — classic (v1) custom format or Berry (v2+) YAML
fn parse_yarn_lock(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    // Yarn Berry lockfiles are YAML with a __metadata block. The classic
    // parser reads them as 0 deps — npm ecosystem silently unscanned.
    if content.contains("__metadata:") {
        return parse_yarn_berry_lock(&content);
    }

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

/// Parse Yarn Berry (v2+) yarn.lock — YAML where keys are descriptor lists
/// like `"axios@npm:^1.6.0, axios@npm:^1.7.0"` and values carry `version`.
fn parse_yarn_berry_lock(content: &str) -> Result<Vec<Dependency>> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(content).context("Failed to parse yarn.lock as YAML (Berry)")?;

    let mut deps = Vec::new();

    if let Some(mapping) = yaml.as_mapping() {
        for (key, val) in mapping {
            let Some(key_str) = key.as_str() else {
                continue;
            };
            if key_str == "__metadata" {
                continue;
            }
            let Some(version) = val.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            // First descriptor of the comma list, e.g. "@scope/pkg@npm:^1.0.0"
            let descriptor = key_str.split(',').next().unwrap_or(key_str).trim();
            if let Some(name) = descriptor_name(descriptor) {
                deps.push(Dependency {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: Ecosystem::Npm,
                });
            }
        }
    }

    deps.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    deps.dedup_by(|a, b| a.name == b.name && a.version == b.version);

    Ok(deps)
}

/// Extract the package name from a yarn descriptor (`pkg@npm:^1`,
/// `@scope/pkg@npm:^1`, `pkg@patch:pkg@npm%3A1#...`). The name ends at the
/// first '@' after the optional leading scope '@'.
fn descriptor_name(descriptor: &str) -> Option<&str> {
    let search_from = if descriptor.starts_with('@') { 1 } else { 0 };
    let at = descriptor[search_from..].find('@')? + search_from;
    if at == 0 {
        return None;
    }
    Some(&descriptor[..at])
}

/// Parse pnpm-lock.yaml
fn parse_pnpm_lock(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    let mut deps = Vec::new();

    // pnpm v6: "/axios@1.7.2", pnpm v9: "axios@1.7.2" — either form may
    // carry peer-dep suffixes: "/axios@1.7.2(react@18.2.0)". The suffix
    // must be stripped BEFORE locating the version separator, otherwise
    // the recorded version is polluted ("1.7.2(react@18.2.0)" or worse)
    // and indicator exact-matching silently never hits.
    if let Some(packages) = yaml.get("packages").and_then(|p| p.as_mapping()) {
        for (key, _val) in packages {
            if let Some(key_str) = key.as_str() {
                let key_str = key_str.trim_start_matches('/');
                let key_str = key_str.split('(').next().unwrap_or(key_str);
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
    fn test_parse_package_lock_alias_uses_real_name() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "test-project", "version": "1.0.0" },
                "node_modules/my-alias": { "name": "axios", "version": "1.14.1" }
            }
        }"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), json).unwrap();

        let deps = parse_package_lock(tmp.path()).unwrap();
        assert_eq!(deps.len(), 1);
        // The malicious axios hides behind an alias — we must see "axios"
        assert_eq!(deps[0].name, "axios");
        assert_eq!(deps[0].version, "1.14.1");
    }

    #[test]
    fn test_parse_pnpm_lock_peer_suffix() {
        let content = r#"
lockfileVersion: '6.0'
packages:
  /axios@1.14.1(debug@4.3.4):
    resolution: {integrity: sha512-xyz}
  /@scope/pkg@2.0.0(react@18.2.0)(react-dom@18.2.0):
    resolution: {integrity: sha512-abc}
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let deps = parse_pnpm_lock(tmp.path()).unwrap();
        assert_eq!(deps.len(), 2);
        // Peer suffix must not pollute the version — exact-match depends on it
        assert!(deps
            .iter()
            .any(|d| d.name == "axios" && d.version == "1.14.1"));
        assert!(deps
            .iter()
            .any(|d| d.name == "@scope/pkg" && d.version == "2.0.0"));
    }

    #[test]
    fn test_parse_pnpm_v9_no_leading_slash() {
        let content = r#"
lockfileVersion: '9.0'
packages:
  axios@1.14.1:
    resolution: {integrity: sha512-xyz}
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let deps = parse_pnpm_lock(tmp.path()).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "axios");
        assert_eq!(deps[0].version, "1.14.1");
    }

    #[test]
    fn test_parse_yarn_berry_lock() {
        let content = r#"# This file is generated by running "yarn install"

__metadata:
  version: 8
  cacheKey: 10c0

"axios@npm:^1.6.0, axios@npm:^1.7.0":
  version: 1.14.1
  resolution: "axios@npm:1.14.1"

"@babel/core@npm:^7.0.0":
  version: 7.23.0
  resolution: "@babel/core@npm:7.23.0"
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        // Berry lockfiles used to parse to 0 deps (silently unscanned)
        let deps = parse_yarn_lock(tmp.path()).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "axios" && d.version == "1.14.1"));
        assert!(deps
            .iter()
            .any(|d| d.name == "@babel/core" && d.version == "7.23.0"));
    }

    #[test]
    fn test_descriptor_name() {
        assert_eq!(descriptor_name("axios@npm:^1.6.0"), Some("axios"));
        assert_eq!(descriptor_name("@scope/pkg@npm:^1.0.0"), Some("@scope/pkg"));
        assert_eq!(
            descriptor_name("typescript@patch:typescript@npm%3A5.0.0#builtin"),
            Some("typescript")
        );
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
