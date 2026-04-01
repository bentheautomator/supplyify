# Contributing to supplyify

Thank you for your interest in improving supplyify. This document outlines how to contribute effectively.

## Code of Conduct

This project adheres to the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## Getting Started

### Prerequisites

- Rust 1.70+
- Git

### Building from Source

```bash
git clone https://github.com/bentheautomator/supplyify
cd supplyify
cargo build --release
./target/release/supplyify --help
```

### Testing

```bash
cargo test
cargo test --lib
cargo test --doc
```

### Code Quality

We use strict quality standards:

```bash
# Format check
cargo fmt --check

# Lint check (must pass cleanly)
cargo clippy -- -D warnings

# Full build + test sequence (use before committing)
make ship
```

All code must pass `cargo fmt` and `cargo clippy -D warnings` without errors.

## Types of Contributions

### 1. Adding New Malicious Package Indicators

The most valuable contributions are new indicators — known-bad packages and versions.

#### Process

1. **Verify the threat** — Confirm the package/version is genuinely malicious
   - Check [Socket.dev](https://socket.dev), OSV.dev, or security advisories
   - Document the source

2. **Add to `src/indicators/bundled.toml`**

   ```toml
   [[malicious_version]]
   ecosystem = "npm"
   package = "compromised-pkg"
   version = "1.2.3"
   severity = "critical"
   description = "Account takeover, drops malware via build script"
   date = "2026-03-15"
   c2_hosts = ["attacker.com:8000", "evil.example.com"]
   tags = ["rat", "postinstall", "account-takeover"]
   reference = "https://socket.dev/blog/..."
   ```

3. **Fields explained**

   | Field | Required | Notes |
   |-------|----------|-------|
   | `ecosystem` | Yes | `npm`, `cargo`, or `pip` |
   | `package` | Yes | Package name (exact case) |
   | `version` | Yes | Affected version (semver format) |
   | `severity` | Yes | `critical`, `high`, `medium`, or `low` |
   | `description` | Yes | 1-2 sentences describing the attack |
   | `date` | Yes | ISO 8601 format (YYYY-MM-DD) |
   | `c2_hosts` | No | Array of command-and-control IPs/domains |
   | `tags` | No | Array of attack categories |
   | `reference` | No | URL to advisory or blog post |

4. **Test your change**

   ```bash
   cargo test
   cargo build --release

   # Test with the new indicator
   ./target/release/supplyify check compromised-pkg@1.2.3
   # Should show: CRITICAL ... description ...
   ```

5. **Submit a PR** with:
   - Single commit with clear message
   - Description of the threat
   - Link to source/advisory

#### Example: Adding the axios compromise

```toml
[[malicious_version]]
ecosystem = "npm"
package = "axios"
version = "1.14.1"
severity = "critical"
description = "Account takeover via phishing, installs plain-crypto-js RAT via postinstall"
date = "2026-03-27"
c2_hosts = ["sfrclak.com:8000", "142.11.206.73"]
tags = ["rat", "postinstall", "account-takeover", "credential-theft"]
reference = "https://socket.dev/blog/axios-npm-package-compromised"
```

### 2. Adding Support for New Ecosystems

supplyify can be extended to scan package managers beyond npm, Cargo, and pip.

#### Process

1. **Create a new ecosystem module** in `src/ecosystems/`

   ```rust
   // src/ecosystems/composer.rs
   use crate::types::{Dependency, DependencySource};

   pub struct ComposerParser;

   impl ComposerParser {
       pub fn detect(path: &Path) -> bool {
           path.join("composer.lock").exists()
       }

       pub fn parse(path: &Path) -> Result<Vec<Dependency>> {
           // Parse composer.lock and return dependencies
       }
   }
   ```

2. **Define the detection logic**
   - Identify lockfile names
   - Parse format (TOML, JSON, YAML, etc.)
   - Extract package name, version, and source

3. **Add to `src/ecosystems/mod.rs`**

   ```rust
   pub mod composer;

   pub fn detect_and_parse(path: &Path) -> Result<Vec<Dependency>> {
       if composer::ComposerParser::detect(path) {
           return composer::ComposerParser::parse(path);
       }
       // ... other parsers
   }
   ```

4. **Update `Ecosystem` enum** in `src/types.rs`

   ```rust
   #[derive(Debug, Clone, PartialEq)]
   pub enum Ecosystem {
       Npm,
       Cargo,
       Pip,
       Composer,  // Add new variant
   }
   ```

5. **Write tests**

   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn test_parse_composer_lock() {
           // Create a test composer.lock
           // Assert parsing works correctly
       }
   }
   ```

6. **Test thoroughly**

   ```bash
   cargo test
   # Test with a real composer.lock file
   supplyify scan /path/to/php-project
   ```

#### Ecosystem Parser Checklist

- [ ] Lockfile detection working
- [ ] Parsing handles current format version
- [ ] Extracts name, version, source
- [ ] Handles edge cases (missing fields, unusual versions)
- [ ] Tests cover normal and edge cases
- [ ] Documentation updated

### 3. Improving Heuristics

The heuristics engine (Layer 2) detects anomalies without requiring a database lookup.

#### Current Heuristics

- **Postinstall scripts** — Unusual script execution before/after install
- **Version anomalies** — Jumps in semver, suspicious pre-release strings

#### Adding a New Heuristic

1. **Create in `src/heuristics/`**

   ```rust
   // src/heuristics/entropy.rs
   pub fn check_version_entropy(version: &str) -> Option<Finding> {
       // Detect unusually random-looking versions
       // Return Finding if anomaly detected
   }
   ```

2. **Register in `src/heuristics/mod.rs`**

   ```rust
   pub fn run_all(dep: &Dependency) -> Vec<Finding> {
       let mut findings = Vec::new();
       findings.extend(postinstall::check(dep));
       findings.extend(version::check(dep));
       findings.extend(entropy::check_version_entropy(&dep.version));
       findings
   }
   ```

3. **Tune false positives** — Heuristics should be precise
   - Test against a large corpus of legitimate packages
   - Document threshold values

4. **Test and benchmark**

   ```bash
   cargo test --lib heuristics::
   cargo build --release && time supplyify scan large-project/
   ```

### 4. Bug Reports and Features

See `.github/ISSUE_TEMPLATE/` for templates.

## Rust Style Guide

We follow standard Rust conventions with these requirements:

### Formatting

```bash
cargo fmt --all
```

All code must be properly formatted. This is checked in CI.

### Linting

```bash
cargo clippy -- -D warnings
```

All clippy warnings must be fixed. No `#[allow(...)]` without justification.

### Naming

- Functions: `snake_case`
- Types: `PascalCase`
- Constants: `SCREAMING_SNAKE_CASE`
- Private functions prefixed with `_` if intentionally internal

### Error Handling

Use `anyhow::Result<T>` for recoverable errors:

```rust
pub fn scan_project(path: &Path) -> Result<ScanResult> {
    let lockfile = find_lockfile(path)?;
    let deps = parse_lockfile(&lockfile)?;
    Ok(analyze(deps))
}
```

Prefer explicit error messages:

```rust
anyhow::bail!("Invalid ecosystem: {}", name);
```

### Documentation

Public API items must have doc comments:

```rust
/// Scans a project directory for supply chain threats.
///
/// # Arguments
///
/// * `path` - Path to project root
/// * `skip_osv` - Skip OSV.dev lookups (offline mode)
///
/// # Returns
///
/// A `ScanResult` containing all detected findings
///
/// # Errors
///
/// Returns error if lockfile cannot be parsed
pub fn scan(path: &Path, skip_osv: bool) -> Result<ScanResult> {
    // ...
}
```

### Testing

Write tests for new public functions:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_malicious_version() {
        let dep = Dependency {
            ecosystem: Ecosystem::Npm,
            name: "axios".to_string(),
            version: "1.14.1".to_string(),
            source: DependencySource::Manifest,
        };

        let findings = scan_dependency(&dep).unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
```

## Pull Request Process

1. **Create a branch** for your changes

   ```bash
   git fetch origin main
   git checkout -b fix/description-or-feature/description main
   ```

2. **Make your changes**
   - One logical change per commit
   - Write descriptive commit messages

3. **Test locally**

   ```bash
   make ship
   ```

4. **Push to your fork**

   ```bash
   git push -u origin your-branch
   ```

5. **Open a PR** with:
   - Clear title and description
   - Reference to any related issues
   - Checklist completed (see PR template)

6. **Respond to review feedback**
   - Address all comments
   - Re-test after changes
   - Don't force-push (reviewers can see conversation context)

### PR Checklist

- [ ] Tests added/updated
- [ ] `cargo fmt` and `cargo clippy` pass
- [ ] Documentation updated (if applicable)
- [ ] Commit message follows conventional format
- [ ] No unrelated changes

## Issue Labels

We use labels to organize work:

- `bug` — Something is broken
- `enhancement` — New feature or improvement
- `documentation` — Docs need updating
- `ecosystem` — Add support for a new package manager
- `indicator` — New malicious package to add
- `heuristic` — Improve or add detection heuristic
- `performance` — Speed or memory improvements
- `security` — Security vulnerability or hardening
- `question` — Question about usage

## Release Process

1. Update version in `Cargo.toml`
2. Update CHANGELOG
3. Commit with message: `chore(release): bump to v0.2.0`
4. Tag: `git tag v0.2.0`
5. Push: `git push origin main --tags`
6. GitHub Actions builds and publishes release

## Questions?

- Open an issue with `question` label
- Check existing discussions in Issues

Thank you for contributing to supply chain security!
