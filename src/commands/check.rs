use anyhow::Result;
use colored::Colorize;

use supplyify::indicators::IndicatorDb;
use supplyify::{Config, Ecosystem};

pub fn run(config: &Config, query: &str) -> Result<()> {
    // Parse query: "package@version" or "ecosystem:package@version"
    let (ecosystem, package, version) = parse_query(query)?;

    let db = IndicatorDb::load()?;

    // Check all ecosystems if none specified
    let ecosystems = if let Some(eco) = ecosystem {
        vec![eco]
    } else {
        vec![Ecosystem::Npm, Ecosystem::Cargo, Ecosystem::Pip]
    };

    let mut found = false;

    for eco in &ecosystems {
        if let Some(mv) = db.check_version(*eco, package, version) {
            found = true;
            if config.format == "json" {
                println!("{}", serde_json::to_string_pretty(mv)?);
            } else {
                println!(
                    "{} {}@{} ({}) — {}",
                    mv.severity.to_string().red().bold(),
                    package.cyan(),
                    version.green(),
                    eco,
                    mv.description
                );
                if !mv.c2.is_empty() {
                    println!("  C2: {}", mv.c2.join(", ").red());
                }
                if !mv.references.is_empty() {
                    for r in &mv.references {
                        println!("  Ref: {}", r.dimmed());
                    }
                }
            }
        }

        if let Some(mp) = db.check_package(*eco, package) {
            found = true;
            if config.format != "json" {
                println!(
                    "{} {} ({}) — entire package malicious: {}",
                    mp.severity.to_string().red().bold(),
                    package.cyan(),
                    eco,
                    mp.description
                );
            }
        }
    }

    if !found {
        if config.format == "json" {
            println!("{{\"status\": \"clean\", \"query\": \"{}\"}}", query);
        } else {
            println!(
                "{} {}@{} — not found in indicator database",
                "✓".green(),
                package,
                version
            );
        }
    }

    Ok(())
}

fn parse_query(query: &str) -> Result<(Option<Ecosystem>, &str, &str)> {
    // Handle "ecosystem:package@version"
    let (eco, rest) = if let Some((eco_str, rest)) = query.split_once(':') {
        let eco = match eco_str {
            "npm" => Some(Ecosystem::Npm),
            "cargo" => Some(Ecosystem::Cargo),
            "pip" | "python" => Some(Ecosystem::Pip),
            _ => None,
        };
        (eco, rest)
    } else {
        (None, query)
    };

    // Handle "package@version"
    let (package, version) = rest.rsplit_once('@').ok_or_else(|| {
        anyhow::anyhow!("Invalid query format. Expected: package@version (e.g., axios@1.14.1)")
    })?;

    Ok((eco, package, version))
}
