use anyhow::Result;
use clap::{Parser, Subcommand};

use supplyify::{OutputFormat, ScanOptions, Severity};

mod commands;

#[derive(Parser)]
#[command(name = "supplyify", version, about = "Supply chain attack detection")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text, global = true)]
    format: OutputFormat,

    /// Write output to file (default: stdout)
    #[arg(short, long, global = true)]
    output: Option<String>,

    /// Suppress informational output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Skip Layer 3 codemap deep analysis of flagged packages
    #[arg(long, global = true)]
    no_codemap: bool,

    /// Skip Layer 2 heuristics (indicator-only scan)
    #[arg(long, global = true)]
    no_heuristics: bool,

    /// Skip OSV.dev online vulnerability lookup (offline mode)
    #[arg(long, global = true)]
    no_osv: bool,

    /// Minimum severity that fails the scan with exit code 1 (lower
    /// severities exit 2)
    #[arg(long, value_enum, default_value_t = Severity::High, global = true)]
    fail_on: Severity,

    /// Fail closed: a degraded scan (OSV unreachable, unparseable
    /// lockfile) exits 3 instead of passing as clean
    #[arg(long, global = true)]
    strict: bool,

    /// Check if a newer version of supplyify is available
    #[arg(long, global = true)]
    check_update: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a project for supply chain threats (all detection layers)
    Scan {
        /// Path to project directory
        #[arg(default_value = ".")]
        path: String,
    },

    /// Find and scan all projects under a directory
    Sweep {
        /// Root directory to sweep
        path: String,
        /// Max parallel project scans
        #[arg(long, default_value = "4")]
        parallel: usize,
    },

    /// Pull latest indicators from the remote feed (checksum-verified)
    Update,

    /// Quick lookup: is this package@version known-bad? Checks local
    /// indicators AND OSV.dev (use --no-osv for offline). Exit 1 on hit.
    Check {
        /// Package query (e.g., axios@1.14.1 or npm:axios@1.14.1)
        query: String,
    },

    /// List current indicator database stats
    Indicators,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.check_update {
        commands::check_update::run();
        if cli.command.is_none() {
            return Ok(());
        }
    }

    let config = supplyify::Config {
        format: cli.format,
        output: cli.output,
        quiet: cli.quiet,
        scan: ScanOptions {
            osv: !cli.no_osv,
            heuristics: !cli.no_heuristics,
            codemap: !cli.no_codemap,
            strict: cli.strict,
            fail_on: cli.fail_on,
        },
    };

    let Some(command) = cli.command else {
        anyhow::bail!("No command given. Try: supplyify scan .  (or --help)");
    };

    match command {
        Commands::Scan { path } => commands::scan::run(&config, &path),
        Commands::Sweep { path, parallel } => commands::sweep::run(&config, &path, parallel),
        Commands::Update => commands::update::run(&config),
        Commands::Check { query } => commands::check::run(&config, &query),
        Commands::Indicators => commands::indicators::run(&config),
    }
}
