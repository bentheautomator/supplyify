use anyhow::Result;
use colored::Colorize;

use supplyify::indicators::IndicatorDb;
use supplyify::Config;

const FEED_URL: &str =
    "https://raw.githubusercontent.com/bentheautomator/supplyify-indicators/main/indicators.toml";

pub fn run(config: &Config) -> Result<()> {
    if !config.quiet {
        eprintln!("{} Checking for indicator updates...", "supplyify".bold());
    }

    let current = IndicatorDb::load()?;
    let current_versions: std::collections::HashSet<(String, String)> = current
        .malicious_version
        .iter()
        .map(|mv| (mv.package.clone(), mv.version.clone()))
        .collect();
    let current_packages: std::collections::HashSet<String> = current
        .malicious_package
        .iter()
        .map(|mp| mp.package.clone())
        .collect();
    let current_total = current.malicious_version.len()
        + current.malicious_package.len()
        + current.c2_indicator.len()
        + current.suspicious_range.len();

    // Fetch remote indicators
    let resp = reqwest::blocking::get(FEED_URL);
    match resp {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text()?;
            let remote = IndicatorDb::from_toml(&body)?;

            // Track what's new before merging
            let new_versions: Vec<_> = remote
                .malicious_version
                .iter()
                .filter(|mv| !current_versions.contains(&(mv.package.clone(), mv.version.clone())))
                .collect();
            let new_packages: Vec<_> = remote
                .malicious_package
                .iter()
                .filter(|mp| !current_packages.contains(&mp.package))
                .collect();

            let new_count = new_versions.len() + new_packages.len();

            // Show what's new
            if !config.quiet && new_count > 0 {
                eprintln!("\n  {}", "New indicators:".yellow().bold());
                for mv in &new_versions {
                    eprintln!(
                        "    {} {}@{} — {}",
                        mv.severity.to_string().red(),
                        mv.package.cyan(),
                        mv.version.green(),
                        mv.description
                    );
                    for r in &mv.references {
                        eprintln!("      Ref: {}", r.dimmed());
                    }
                }
                for mp in &new_packages {
                    eprintln!(
                        "    {} {} — {}",
                        mp.severity.to_string().red(),
                        mp.package.cyan(),
                        mp.description
                    );
                }
            }

            // Merge and save
            let mut merged = current;
            merged.merge(remote);

            let merged_total = merged.malicious_version.len()
                + merged.malicious_package.len()
                + merged.c2_indicator.len()
                + merged.suspicious_range.len();

            if let Some(config_path) = IndicatorDb::user_config_path() {
                if let Some(parent) = config_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let toml_str = toml::to_string_pretty(&merged)?;
                std::fs::write(&config_path, &toml_str)?;

                if !config.quiet {
                    eprintln!();
                    if new_count > 0 {
                        eprintln!(
                            "  {} {} new indicators added (total: {})",
                            "✓".green(),
                            new_count.to_string().green(),
                            merged_total
                        );
                    } else {
                        eprintln!(
                            "  {} Already up to date ({} indicators)",
                            "✓".green(),
                            merged_total
                        );
                    }
                    eprintln!(
                        "  {} Saved to {}",
                        "✓".green(),
                        config_path.display().to_string().dimmed()
                    );
                }
            }
        }
        Ok(resp) => {
            if !config.quiet {
                eprintln!(
                    "  {} Feed returned HTTP {} — using bundled + local indicators ({} total)",
                    "!".yellow(),
                    resp.status(),
                    current_total
                );
                eprintln!(
                    "  {} Scans still query OSV.dev live (80K+ advisories) unless --no-osv is set",
                    "i".cyan()
                );
            }
        }
        Err(_) => {
            if !config.quiet {
                eprintln!(
                    "  {} Feed unreachable — using bundled + local indicators ({} total)",
                    "!".yellow(),
                    current_total
                );
                eprintln!(
                    "  {} Scans still query OSV.dev live (80K+ advisories) unless --no-osv is set",
                    "i".cyan()
                );
            }
        }
    }

    Ok(())
}
