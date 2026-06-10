use anyhow::Result;
use colored::Colorize;

use supplyify::indicators::IndicatorDb;
use supplyify::{Config, Dependency, Ecosystem, Finding, OutputFormat};

/// `supplyify check pkg@ver` — the pre-install gate primitive.
/// Checks local indicators (versions, whole packages, ranges) AND OSV.dev
/// unless --no-osv. Exit codes: 0 clean, 1 known-bad, 3 lookup degraded
/// in --strict mode.
pub fn run(config: &Config, query: &str) -> Result<()> {
    let (ecosystem, package, version) = parse_query(query)?;

    let db = IndicatorDb::load()?;

    let ecosystems = if let Some(eco) = ecosystem {
        vec![eco]
    } else {
        vec![
            Ecosystem::Npm,
            Ecosystem::Cargo,
            Ecosystem::Pip,
            Ecosystem::Go,
        ]
    };

    let mut hits: Vec<String> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut degraded = false;

    for eco in &ecosystems {
        if let Some(mv) = db.check_version(*eco, package, version) {
            hits.push(format!(
                "{} {}@{} ({}) — {}",
                mv.severity, package, version, eco, mv.description
            ));
            if config.is_human() {
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
                for r in &mv.references {
                    println!("  Ref: {}", r.dimmed());
                }
            }
        }

        if let Some(mp) = db.check_package(*eco, package) {
            hits.push(format!(
                "{} {} ({}) — entire package malicious: {}",
                mp.severity, package, eco, mp.description
            ));
            if config.is_human() {
                println!(
                    "{} {} ({}) — entire package malicious: {}",
                    mp.severity.to_string().red().bold(),
                    package.cyan(),
                    eco,
                    mp.description
                );
            }
        }

        // Suspicious ranges were previously not checked at all
        if let Some(sr) = db.check_range(*eco, package, version) {
            hits.push(format!(
                "{} {}@{} ({}) — in suspicious range {}: {}",
                sr.severity, package, version, eco, sr.range, sr.description
            ));
            if config.is_human() {
                println!(
                    "{} {}@{} ({}) — in suspicious range {}: {}",
                    sr.severity.to_string().red().bold(),
                    package.cyan(),
                    version.green(),
                    eco,
                    sr.range,
                    sr.description
                );
            }
        }
    }

    // OSV.dev lookup — `check` previously consulted only the local DB and
    // printed a reassuring green check against ~a handful of indicators.
    if config.scan.osv {
        let deps: Vec<Dependency> = ecosystems
            .iter()
            .map(|eco| Dependency {
                name: package.to_string(),
                version: version.to_string(),
                ecosystem: *eco,
            })
            .collect();
        let dep_refs: Vec<&Dependency> = deps.iter().collect();
        let outcome = supplyify::osv::query_batch(&dep_refs);
        degraded = !outcome.warnings.is_empty();
        for w in &outcome.warnings {
            if !config.quiet {
                eprintln!("  {} {}", "!".yellow(), w);
            }
        }
        for f in &outcome.findings {
            hits.push(format!(
                "{} {}@{} — {} ({})",
                f.severity,
                f.package,
                f.version,
                f.description,
                f.kind.name()
            ));
            if config.is_human() {
                println!(
                    "{} {}@{} — {}",
                    f.severity.to_string().red().bold(),
                    f.package.cyan(),
                    f.version.green(),
                    f.description
                );
                if let Some(ref url) = f.details.advisory_url {
                    println!("  Advisory: {}", url.underline());
                }
            }
        }
        findings.extend(outcome.findings);
    }

    match config.format {
        OutputFormat::Json => {
            let payload = serde_json::json!({
                "query": query,
                "status": if hits.is_empty() { "clean" } else { "known-bad" },
                "hits": hits,
                "findings": findings,
                "degraded": degraded,
                "osv_checked": config.scan.osv,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Agent => {
            println!(
                "SUPPLYIFY|{}|1\nCMD|check\nQUERY|{}",
                env!("CARGO_PKG_VERSION"),
                query
            );
            for hit in &hits {
                println!("HIT|{}", hit);
            }
            if degraded {
                println!("DEGRADED|true");
            }
            println!(
                "RESULT|{}",
                if hits.is_empty() {
                    "clean"
                } else {
                    "known-bad"
                }
            );
        }
        _ => {
            if hits.is_empty() {
                let coverage = if config.scan.osv && !degraded {
                    "local indicators + OSV.dev"
                } else {
                    "local indicators only"
                };
                println!(
                    "{} {}@{} — no known threats ({})",
                    "✓".green(),
                    package,
                    version,
                    coverage
                );
            }
        }
    }

    if !hits.is_empty() {
        std::process::exit(1);
    }
    if degraded && config.scan.strict {
        std::process::exit(3);
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
            "go" => Some(Ecosystem::Go),
            _ => None,
        };
        (eco, rest)
    } else {
        (None, query)
    };

    // Handle "package@version" (scoped npm names contain a leading '@')
    let (package, version) = rest.rsplit_once('@').ok_or_else(|| {
        anyhow::anyhow!("Invalid query format. Expected: package@version (e.g., axios@1.14.1)")
    })?;
    if package.is_empty() || version.is_empty() {
        anyhow::bail!("Invalid query format. Expected: package@version (e.g., axios@1.14.1)");
    }

    Ok((eco, package, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_query() {
        let (eco, pkg, ver) = parse_query("axios@1.14.1").unwrap();
        assert!(eco.is_none());
        assert_eq!(pkg, "axios");
        assert_eq!(ver, "1.14.1");
    }

    #[test]
    fn parse_ecosystem_query() {
        let (eco, pkg, ver) = parse_query("npm:axios@1.14.1").unwrap();
        assert_eq!(eco, Some(Ecosystem::Npm));
        assert_eq!(pkg, "axios");
        assert_eq!(ver, "1.14.1");
    }

    #[test]
    fn parse_scoped_package() {
        let (_, pkg, ver) = parse_query("@scope/pkg@2.0.0").unwrap();
        assert_eq!(pkg, "@scope/pkg");
        assert_eq!(ver, "2.0.0");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_query("no-version").is_err());
        assert!(parse_query("@1.0.0").is_err());
    }
}
