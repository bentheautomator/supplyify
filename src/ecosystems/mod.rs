pub mod cargo;
pub mod golang;
pub mod npm;
pub mod pip;

use anyhow::Result;
use std::path::{Path, PathBuf};

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
        Box::new(golang::GoParser),
    ]
}

/// One ecosystem found in a project, with the lockfile it came from
pub struct DiscoveredEcosystem {
    pub ecosystem: Ecosystem,
    pub lockfile: PathBuf,
    pub deps: Vec<Dependency>,
}

/// Result of project discovery. A parse failure is a warning, not a
/// silent skip — an unparseable lockfile means the ecosystem was NOT
/// scanned, and the caller must be able to tell.
pub struct Discovery {
    pub ecosystems: Vec<DiscoveredEcosystem>,
    pub warnings: Vec<String>,
}

/// Discover which ecosystems are present in a project directory
pub fn discover_project(path: &Path) -> Discovery {
    let mut discovery = Discovery {
        ecosystems: Vec::new(),
        warnings: Vec::new(),
    };

    for parser in all_parsers() {
        // Check for lockfiles first (more precise)
        for lockfile in parser.lockfile_names() {
            let lockfile_path = path.join(lockfile);
            if !lockfile_path.exists() {
                continue;
            }
            match parser.parse_lockfile(&lockfile_path) {
                Ok(deps) => {
                    if deps.is_empty() {
                        discovery.warnings.push(format!(
                            "{}: parsed 0 dependencies — file may use an unsupported format",
                            lockfile_path.display()
                        ));
                    }
                    discovery.ecosystems.push(DiscoveredEcosystem {
                        ecosystem: parser.ecosystem(),
                        lockfile: lockfile_path,
                        deps,
                    });
                    break; // Only parse first lockfile found per ecosystem
                }
                Err(e) => {
                    discovery.warnings.push(format!(
                        "{}: parse failed ({}) — {} dependencies NOT scanned",
                        lockfile_path.display(),
                        e,
                        parser.ecosystem()
                    ));
                }
            }
        }
    }

    discovery
}
