use anyhow::Result;
use colored::Colorize;
use std::path::Path;
use std::time::Instant;

use supplyify::sweep as sweep_mod;
use supplyify::{output, Config, ScanResult, Severity};

/// Worst exit code across the sweep, by badness: 1 (findings at/above
/// fail_on) > 3 (degraded in strict mode) > 2 (lesser findings) > 0.
fn worst_exit_code(results: &[ScanResult], config: &Config) -> i32 {
    let rank = |code: i32| match code {
        1 => 3,
        3 => 2,
        2 => 1,
        _ => 0,
    };
    results
        .iter()
        .map(|r| r.exit_code(&config.scan))
        .max_by_key(|c| rank(*c))
        .unwrap_or(0)
}

pub fn run(config: &Config, path: &str, parallel: usize) -> Result<()> {
    let sweep_start = Instant::now();
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

    let results = sweep_mod::sweep(&config.scan, root, parallel);

    if config.format != supplyify::OutputFormat::Text {
        print!("{}", output::format_results(config.format, &results));
        let worst = worst_exit_code(&results, config);
        if worst != 0 {
            std::process::exit(worst);
        }
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
    }

    let worst_exit = worst_exit_code(&results, config);

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
    let duration = supplyify::format_duration_ms(sweep_start.elapsed().as_millis());

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
