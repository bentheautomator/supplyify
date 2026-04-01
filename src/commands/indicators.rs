use anyhow::Result;
use colored::Colorize;

use supplyify::indicators::IndicatorDb;
use supplyify::Config;

pub fn run(config: &Config) -> Result<()> {
    let db = IndicatorDb::load()?;

    if config.format == "json" {
        let stats = serde_json::json!({
            "version": db.meta.version,
            "sources": db.meta.sources,
            "malicious_versions": db.malicious_version.len(),
            "malicious_packages": db.malicious_package.len(),
            "c2_indicators": db.c2_indicator.len(),
            "suspicious_ranges": db.suspicious_range.len(),
        });
        println!("{}", serde_json::to_string_pretty(&stats)?);
        return Ok(());
    }

    println!("{}", "supplyify indicator database".bold());
    println!("  Version:             {}", db.meta.version.green());
    println!(
        "  Sources:             {}",
        db.meta.sources.join(", ").dimmed()
    );
    println!(
        "  Malicious versions:  {}",
        db.malicious_version.len().to_string().yellow()
    );
    println!(
        "  Malicious packages:  {}",
        db.malicious_package.len().to_string().yellow()
    );
    println!(
        "  C2 indicators:       {}",
        db.c2_indicator.len().to_string().yellow()
    );
    println!(
        "  Suspicious ranges:   {}",
        db.suspicious_range.len().to_string().yellow()
    );

    if !config.quiet {
        println!("\n{}", "Recent indicators:".dimmed());
        for mv in db.malicious_version.iter().take(5) {
            println!(
                "  {} {}@{} — {} ({})",
                mv.severity.to_string().red(),
                mv.package.cyan(),
                mv.version,
                mv.description,
                mv.date.dimmed()
            );
        }
    }

    Ok(())
}
