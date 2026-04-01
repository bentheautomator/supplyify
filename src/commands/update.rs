use anyhow::Result;
use colored::Colorize;

use supplyify::indicators::IndicatorDb;
use supplyify::Config;

pub fn run(config: &Config) -> Result<()> {
    if !config.quiet {
        eprintln!("{} Checking for indicator updates...", "supplyify".bold());
    }

    let current = IndicatorDb::load()?;
    let current_count = current.malicious_version.len()
        + current.malicious_package.len()
        + current.c2_indicator.len()
        + current.suspicious_range.len();

    // Fetch remote indicators
    let url = "https://raw.githubusercontent.com/bentheautomator/supplyify-indicators/main/indicators.toml";

    let resp = reqwest::blocking::get(url);
    match resp {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text()?;
            let remote = IndicatorDb::from_toml(&body)?;

            let _remote_count = remote.malicious_version.len()
                + remote.malicious_package.len()
                + remote.c2_indicator.len()
                + remote.suspicious_range.len();

            // Merge
            let mut merged = current;
            merged.merge(remote);

            let merged_count = merged.malicious_version.len()
                + merged.malicious_package.len()
                + merged.c2_indicator.len()
                + merged.suspicious_range.len();

            let new_count = merged_count - current_count;

            // Write to user config
            if let Some(config_path) = IndicatorDb::user_config_path() {
                if let Some(parent) = config_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let toml_str = toml::to_string_pretty(&merged)?;
                std::fs::write(&config_path, toml_str)?;

                if !config.quiet {
                    eprintln!(
                        "  {} {} new indicators (total: {})",
                        "✓".green(),
                        new_count,
                        merged_count
                    );
                    eprintln!(
                        "  Written to {}",
                        config_path.display().to_string().dimmed()
                    );
                }
            }
        }
        Ok(resp) => {
            eprintln!(
                "  {} Remote indicators returned HTTP {} — using bundled only",
                "!".yellow(),
                resp.status()
            );
        }
        Err(e) => {
            eprintln!(
                "  {} Could not fetch remote indicators: {} — using bundled only",
                "!".yellow(),
                e
            );
        }
    }

    Ok(())
}
