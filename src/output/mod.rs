pub mod agent;
pub mod json;
pub mod sarif;
pub mod text;

use crate::{OutputFormat, ScanResult};

/// Format scan results. Format is a typed enum — unknown formats are a
/// CLI parse error, never a silent fallback to text.
pub fn format_results(format: OutputFormat, results: &[ScanResult]) -> String {
    match format {
        OutputFormat::Text => text::format(results),
        OutputFormat::Json => json::format(results),
        OutputFormat::Agent => agent::format(results),
        OutputFormat::Sarif => sarif::format(results),
    }
}
