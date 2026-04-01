use colored::Colorize;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASES_API: &str = "https://api.github.com/repos/bentheautomator/supplyify/releases/latest";

/// Check toolshed registry for a newer version of supplyify
pub fn run() {
    let latest = match fetch_latest_version() {
        Some(v) => v,
        None => {
            eprintln!(
                "  {} Could not check for updates (network or registry unavailable)",
                "!".yellow()
            );
            return;
        }
    };

    if latest == CURRENT_VERSION {
        eprintln!(
            "  {} supplyify {} is up to date",
            "✓".green(),
            CURRENT_VERSION.green()
        );
    } else {
        eprintln!(
            "  {} supplyify {} available (you have {})",
            "↑".yellow(),
            latest.green(),
            CURRENT_VERSION.dimmed()
        );
        eprintln!("  Update: {}", "toolshed update supplyify".cyan());
    }
}

fn fetch_latest_version() -> Option<String> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(RELEASES_API)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "supplyify")
        .send()
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let json: serde_json::Value = resp.json().ok()?;
    let tag = json.get("tag_name")?.as_str()?;
    Some(tag.trim_start_matches('v').to_string())
}
