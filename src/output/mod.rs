pub mod agent;
pub mod json;
pub mod text;

use crate::ScanResult;

/// Format scan results based on format string
pub fn format_results(format: &str, results: &[ScanResult]) -> String {
    match format {
        "json" => json::format(results),
        "agent" => agent::format(results),
        _ => text::format(results),
    }
}
