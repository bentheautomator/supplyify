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
    let exit_code = result.exit_code();
    let output = output::format_results(&config.format, &[result]);

    if let Some(ref output_path) = config.output {
        std::fs::write(output_path, &output)?;
        if !config.quiet {
            eprintln!("Report written to {}", output_path);
        }
    } else {
        print!("{}", output);
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
