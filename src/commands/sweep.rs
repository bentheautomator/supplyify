use anyhow::Result;
use colored::Colorize;
use std::path::Path;

use supplyify::sweep as sweep_mod;
use supplyify::{output, Config, Severity};

pub fn run(config: &Config, path: &str, parallel: usize) -> Result<()> {
    let root = Path::new(path);
    if !root.exists() {
        anyhow::bail!("Path does not exist: {}", root.display());
    }

    let projects = sweep_mod::discover_projects(root);

    if !config.quiet {
        eprintln!(
            "Sweeping {} ... found {} projects\n",
            root.display(),
            projects.len()
        );
    }

    let results = sweep_mod::sweep(config, root, parallel);

    if config.format != "text" {
        print!("{}", output::format_results(&config.format, &results));
        return Ok(());
    }

    // Text output: per-project summary
    let max_name = results
        .iter()
        .map(|r| {
            Path::new(&r.project_path)
                .file_name()
                .map(|f| f.to_string_lossy().len())
                .unwrap_or(10)
        })
        .max()
        .unwrap_or(20);

    let mut worst_exit = 0;

    for result in &results {
        let name = Path::new(&result.project_path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| result.project_path.clone());

        let (c, h, m, l) = result.count_by_severity();

        let status = if c > 0 || h > 0 {
            format!("{}", "CRITICAL".red().bold())
        } else if m > 0 || l > 0 {
            format!("{}", "WARNING".yellow())
        } else {
            format!("{}", "CLEAN".green())
        };

        let detail = if result.findings.is_empty() {
            format!("{} deps", result.dep_count)
        } else {
            let worst = result.findings.iter().map(|f| &f.severity).max().unwrap();
            let worst_pkg = result
                .findings
                .iter()
                .find(|f| f.severity == *worst)
                .unwrap();
            format!("{}@{}", worst_pkg.package, worst_pkg.version)
        };

        println!(
            "  {:<width$}  {:<12}  {}",
            name,
            status,
            detail,
            width = max_name
        );

        let exit = result.exit_code();
        if exit > worst_exit {
            worst_exit = exit;
        }
    }

    let total_deps: usize = results.iter().map(|r| r.dep_count).sum();
    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
    let total_critical: usize = results
        .iter()
        .map(|r| {
            r.findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count()
        })
        .sum();
    let total_ms: u128 = results.iter().map(|r| r.duration_ms).max().unwrap_or(0);
    let duration = if total_ms >= 60_000 {
        format!("{:.1}m", total_ms as f64 / 60_000.0)
    } else if total_ms >= 1_000 {
        format!("{:.1}s", total_ms as f64 / 1_000.0)
    } else {
        format!("{}ms", total_ms)
    };

    println!(
        "\nSummary: {} projects | {} total deps | {} findings ({} critical) | {}",
        results.len(),
        total_deps,
        total_findings,
        total_critical,
        duration
    );

    if worst_exit != 0 {
        std::process::exit(worst_exit);
    }

    Ok(())
}
