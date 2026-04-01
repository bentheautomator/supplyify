# Adding Ecosystem Support

This guide walks through adding support for a new package ecosystem to supplyify.

## Current Ecosystems

| Ecosystem | Parser | Lockfiles |
|-----------|--------|-----------|
| npm | `src/ecosystems/npm.rs` | package-lock.json, yarn.lock, pnpm-lock.yaml |
| Cargo | `src/ecosystems/cargo.rs` | Cargo.lock |
| pip | `src/ecosystems/pip.rs` | requirements.txt, poetry.lock, Pipfile.lock |

## Candidates for New Parsers

| Ecosystem | Lockfiles | Difficulty |
|-----------|-----------|------------|
| Go | go.sum | Easy (line-based) |
| Composer (PHP) | composer.lock | Easy (JSON) |
| Bundler (Ruby) | Gemfile.lock | Medium (custom format) |
| Maven (Java) | pom.xml + dependency tree | Hard (XML, no lockfile) |
| NuGet (.NET) | packages.lock.json | Easy (JSON) |

## Step 1: Create the Parser Module

Create `src/ecosystems/youreco.rs`:

```rust
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

fn parse_go_sum(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut deps = Vec::new();

    for line in content.lines() {
        // go.sum format: module version hash
        // e.g., github.com/gin-gonic/gin v1.9.1 h1:abc123=
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0];
            let version = parts[1].trim_start_matches('v');
            // Skip /go.mod entries (only keep source entries)
            if !version.ends_with("/go.mod") {
                deps.push(Dependency {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: Ecosystem::Go,
                });
            }
        }
    }

    // Dedup (go.sum has hash + go.mod lines for each dep)
    deps.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    deps.dedup_by(|a, b| a.name == b.name && a.version == b.version);

    Ok(deps)
}
```

## Step 2: Add the Ecosystem Variant

If your ecosystem isn't already in the `Ecosystem` enum in `src/lib.rs`, the variants `Go`, `Composer`, and `Bundler` are already defined. If you need a new one, add it there.

## Step 3: Register the Parser

In `src/ecosystems/mod.rs`:

```rust
pub mod go;  // Add this line

pub fn all_parsers() -> Vec<Box<dyn EcosystemParser>> {
    vec![
        Box::new(npm::NpmParser),
        Box::new(cargo::CargoParser),
        Box::new(pip::PipParser),
        Box::new(go::GoParser),  // Add this line
    ]
}
```

## Step 4: Write Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_go_sum() {
        let content = "github.com/gin-gonic/gin v1.9.1 h1:abc=\n\
                        github.com/gin-gonic/gin v1.9.1/go.mod h1:def=\n\
                        golang.org/x/net v0.17.0 h1:ghi=\n";

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let deps = parse_go_sum(tmp.path()).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "github.com/gin-gonic/gin"));
    }
}
```

## Step 5: Test Against Real Projects

```bash
cargo build
./target/debug/supplyify scan /path/to/go-project
```

## Ecosystem Parser Checklist

- [ ] Implements `EcosystemParser` trait
- [ ] All lockfile formats for the ecosystem are supported
- [ ] Handles edge cases (empty files, malformed entries, comments)
- [ ] Deduplicates entries (lockfiles often have duplicate lines)
- [ ] Only includes registry packages (skips local/path dependencies)
- [ ] Unit tests with fixture data
- [ ] Tested against at least one real project
- [ ] Added to `all_parsers()` in `mod.rs`

## Lockfile Format Tips

| Format | Parsing Approach |
|--------|-----------------|
| JSON | `serde_json::Value` or typed deserialization |
| TOML | `toml::from_str` with typed structs |
| YAML | `serde_yaml::from_str` |
| Line-based | `content.lines()` with split/parse |
| Custom (yarn.lock, Gemfile.lock) | State machine or regex |
