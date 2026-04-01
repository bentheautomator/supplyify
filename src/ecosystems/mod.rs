pub mod cargo;
pub mod npm;
pub mod pip;

use anyhow::Result;
use std::path::Path;

use crate::{Dependency, Ecosystem};

/// Trait for parsing lockfiles and manifests of a specific ecosystem
pub trait EcosystemParser {
    fn ecosystem(&self) -> Ecosystem;
    fn lockfile_names(&self) -> &[&str];
    fn manifest_names(&self) -> &[&str];
    fn parse_lockfile(&self, path: &Path) -> Result<Vec<Dependency>>;
}

/// All supported parsers
pub fn all_parsers() -> Vec<Box<dyn EcosystemParser>> {
    vec![
        Box::new(npm::NpmParser),
        Box::new(cargo::CargoParser),
        Box::new(pip::PipParser),
    ]
}

/// Discover which ecosystems are present in a project directory
/// Returns list of (ecosystem, dependencies) tuples
pub fn discover_project(path: &Path) -> Vec<(Ecosystem, Vec<Dependency>)> {
    let mut results = Vec::new();

    for parser in all_parsers() {
        // Check for lockfiles first (more precise)
        for lockfile in parser.lockfile_names() {
            let lockfile_path = path.join(lockfile);
            if lockfile_path.exists() {
                match parser.parse_lockfile(&lockfile_path) {
                    Ok(deps) if !deps.is_empty() => {
                        results.push((parser.ecosystem(), deps));
                        break; // Only parse first lockfile found per ecosystem
                    }
                    Ok(_) => {}  // Empty, try next lockfile
                    Err(_) => {} // Parse error, try next lockfile
                }
            }
        }
    }

    results
}
