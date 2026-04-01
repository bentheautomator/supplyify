use rayon::prelude::*;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::scanner;
use crate::{Config, ScanResult};

/// Lockfile names that indicate a project root
const PROJECT_MARKERS: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
];

/// Find all project directories under a root
pub fn discover_projects(root: &Path) -> Vec<PathBuf> {
    let mut projects = Vec::new();

    // Canonicalize to resolve "." and avoid filtering out the root entry
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    for entry in WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            // Skip hidden dirs, node_modules, target, .git, __pycache__
            !name.starts_with('.')
                && name != "node_modules"
                && name != "target"
                && name != "__pycache__"
                && name != "venv"
        })
        .flatten()
    {
        if entry.file_type().is_file() {
            let name = entry.file_name().to_string_lossy();
            if PROJECT_MARKERS.contains(&name.as_ref()) {
                if let Some(parent) = entry.path().parent() {
                    let parent = parent.to_path_buf();
                    if !projects.contains(&parent) {
                        projects.push(parent);
                    }
                }
            }
        }
    }

    projects
}

/// Sweep: discover and scan all projects in parallel
pub fn sweep(config: &Config, root: &Path, parallelism: usize) -> Vec<ScanResult> {
    let projects = discover_projects(root);

    rayon::ThreadPoolBuilder::new()
        .num_threads(parallelism)
        .build_global()
        .ok(); // Ignore if already built

    projects
        .par_iter()
        .map(|project_path| scanner::scan(config, project_path))
        .collect()
}
