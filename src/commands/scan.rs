use anyhow::Result;
use std::path::Path;

use supplyify::scanner;
use supplyify::{output, Config};

pub fn run(config: &Config, path: &str) -> Result<()> {
    let path = Path::new(path);
    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    let result = scanner::scan(config, path);
    let exit_code = result.exit_code_v3(config.fail_on, config.strict);
    let below_threshold_count = result
        .findings
        .iter()
        .filter(|f| f.severity < config.fail_on)
        .count();
    let output = output::format_results(&config.format, &[result]);

    if let Some(ref output_path) = config.output {
        std::fs::write(output_path, &output)?;
        if !config.quiet {
            eprintln!("Report written to {}", output_path);
        }
    } else {
        print!("{}", output);
    }

    // Surface silent pass: `exit 0 with findings` is easy to misread as clean
    // when the user relied on --fail-on to demote lower-severity findings.
    // Emit a stderr WARN so CI/humans see the findings didn't disappear —
    // the exit code just chose not to gate on them.
    if exit_code == 0 && below_threshold_count > 0 && !config.quiet {
        eprintln!(
            "supplyify: {} finding(s) below --fail-on={} — exiting 0 but findings surface in report",
            below_threshold_count, config.fail_on
        );
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
