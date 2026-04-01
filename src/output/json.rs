use crate::ScanResult;

pub fn format(results: &[ScanResult]) -> String {
    serde_json::to_string_pretty(results).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}
