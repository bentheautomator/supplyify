use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "supplyify", version, about = "Supply chain attack detection")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format: text (default), json, sarif, agent
    #[arg(short, long, default_value = "text", global = true)]
    format: String,

    /// Write output to file (default: stdout)
    #[arg(short, long, global = true)]
    output: Option<String>,

    /// Suppress informational output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Skip Layer 3 codemap analysis
    #[arg(long, global = true)]
    no_codemap: bool,

    /// Skip Layer 2 heuristics (indicator-only scan)
    #[arg(long, global = true)]
    no_heuristics: bool,

    /// Skip OSV.dev online vulnerability lookup (offline mode)
    #[arg(long, global = true)]
    no_osv: bool,

    /// Check if a newer version of supplyify is available
    #[arg(long, global = true)]
    check_update: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a project for supply chain threats (all 3 layers)
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

    /// Pull latest indicators from GitHub feed
    Update,

    /// Quick lookup: is this package@version known-bad?
    Check {
        /// Package query (e.g., axios@1.14.1)
        query: String,
    },

    /// List current indicator database stats
    Indicators,

    /// Generate formatted report
    Report {
        /// Path to project directory
        path: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.check_update {
        commands::check_update::run();
    }

    let config = supplyify::Config {
        format: cli.format,
        output: cli.output,
        quiet: cli.quiet,
        no_codemap: cli.no_codemap,
        no_heuristics: cli.no_heuristics,
        no_osv: cli.no_osv,
    };

    match cli.command {
        Commands::Scan { path } => commands::scan::run(&config, &path),
        Commands::Sweep { path, parallel } => commands::sweep::run(&config, &path, parallel),
        Commands::Update => commands::update::run(&config),
        Commands::Check { query } => commands::check::run(&config, &query),
        Commands::Indicators => commands::indicators::run(&config),
        Commands::Report { path } => commands::scan::run(&config, &path),
    }
}
