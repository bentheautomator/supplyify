//! Integration tests: spawn the actual supplyify binary against fixture
//! projects and lock the exit-code + agent-format contracts.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;

fn supplyify() -> Command {
    Command::cargo_bin("supplyify").unwrap()
}

fn write_lockfile(dir: &Path, entries: &[(&str, &str)]) {
    let packages: Vec<String> = entries
        .iter()
        .map(|(n, v)| format!(r#""node_modules/{}": {{ "version": "{}" }}"#, n, v))
        .collect();
    let json = format!(
        r#"{{"lockfileVersion": 3, "packages": {{ "": {{"name":"t","version":"1.0.0"}}, {} }}}}"#,
        packages.join(",")
    );
    std::fs::write(dir.join("package-lock.json"), json).unwrap();
}

#[test]
fn scan_clean_project_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    write_lockfile(dir.path(), &[("express", "4.18.2")]);

    supplyify()
        .args(["scan", "--no-osv", "-f", "agent"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("SUMMARY|0 critical, 0 high"));
}

#[test]
fn scan_malicious_version_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    write_lockfile(dir.path(), &[("axios", "1.14.1")]);

    supplyify()
        .args(["scan", "--no-osv", "-f", "agent"])
        .arg(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("FINDING|CRITICAL|axios|1.14.1"));
}

#[test]
fn agent_output_has_versioned_header() {
    let dir = tempfile::tempdir().unwrap();
    write_lockfile(dir.path(), &[("express", "4.18.2")]);

    supplyify()
        .args(["scan", "--no-osv", "-f", "agent"])
        .arg(dir.path())
        .assert()
        .stdout(predicate::str::is_match(r"^SUPPLYIFY\|\d+\.\d+\.\d+\|\d+\n").unwrap());
}

#[test]
fn fail_on_critical_demotes_high_to_warning_exit() {
    let dir = tempfile::tempdir().unwrap();
    // axios 0.30.2 hits the bundled suspicious_range (HIGH)
    write_lockfile(dir.path(), &[("axios", "0.30.2")]);

    // Default fail_on=high → exit 1
    supplyify()
        .args(["scan", "--no-osv", "-f", "agent"])
        .arg(dir.path())
        .assert()
        .code(1);

    // fail_on=critical → HIGH is now a warning → exit 2
    supplyify()
        .args(["scan", "--no-osv", "--fail-on", "critical", "-f", "agent"])
        .arg(dir.path())
        .assert()
        .code(2);
}

#[test]
fn strict_mode_fails_closed_on_unparseable_lockfile() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Cargo.lock"), "not [ valid { toml").unwrap();

    // Default: degraded-but-clean passes, but the degradation is visible
    supplyify()
        .args(["scan", "--no-osv", "-f", "agent"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("DEGRADED|true"));

    // Strict: exit 3 — "couldn't scan" is not "clean"
    supplyify()
        .args(["scan", "--no-osv", "--strict", "-f", "agent"])
        .arg(dir.path())
        .assert()
        .code(3);
}

#[test]
fn check_known_bad_exits_one() {
    supplyify()
        .args(["check", "--no-osv", "axios@1.14.1"])
        .assert()
        .code(1);
}

#[test]
fn check_suspicious_range_exits_one() {
    // Ranges were previously not consulted by `check` at all
    supplyify()
        .args(["check", "--no-osv", "axios@0.30.2"])
        .assert()
        .code(1);
}

#[test]
fn check_clean_exits_zero_and_states_coverage() {
    supplyify()
        .args(["check", "--no-osv", "express@4.18.2"])
        .assert()
        .success()
        .stdout(predicate::str::contains("local indicators only"));
}

#[test]
fn check_agent_format() {
    supplyify()
        .args(["check", "--no-osv", "-f", "agent", "axios@1.14.1"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("CMD|check"))
        .stdout(predicate::str::contains("RESULT|known-bad"));
}

#[test]
fn unknown_format_is_a_cli_error_not_silent_text() {
    let dir = tempfile::tempdir().unwrap();
    write_lockfile(dir.path(), &[("express", "4.18.2")]);

    supplyify()
        .args(["scan", "--no-osv", "-f", "yaml"])
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}

#[test]
fn sarif_output_is_valid_json_with_schema() {
    let dir = tempfile::tempdir().unwrap();
    write_lockfile(dir.path(), &[("axios", "1.14.1")]);

    let out = supplyify()
        .args(["scan", "--no-osv", "-f", "sarif"])
        .arg(dir.path())
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let sarif: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "supplyify");
    assert!(!sarif["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn policy_file_suppression_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    write_lockfile(dir.path(), &[("axios", "1.14.1")]);
    std::fs::write(
        dir.path().join(".supplyify.toml"),
        "[[ignore]]\npackage = \"axios\"\nversion = \"1.14.1\"\nreason = \"test\"\n",
    )
    .unwrap();

    supplyify()
        .args(["scan", "--no-osv", "-f", "agent"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("IGNORED|1"));
}

#[test]
fn report_subcommand_removed() {
    supplyify().args(["report", "."]).assert().failure();
}
