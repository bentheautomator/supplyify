//! Ecosystem-tolerant version comparison.
//!
//! Indicator ranges previously used strict semver, which silently never
//! matched pip (PEP 440: `1.2`, `2.0.post1`), Go (`v1.2.3`), or any other
//! non-semver version — a fail-open hole. This module compares with semver
//! when both sides parse, and falls back to a lenient segment-wise
//! comparison otherwise.

use std::cmp::Ordering;

/// Compare two version strings. Returns None only when a string has no
/// comparable content at all.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    if let (Ok(va), Ok(vb)) = (semver::Version::parse(a), semver::Version::parse(b)) {
        return Some(va.cmp(&vb));
    }
    lenient_compare(a, b)
}

/// Lenient comparison: strip a leading 'v', split on `.`, `-`, `_`, `+`,
/// compare segment-wise (numeric when both numeric, else lexicographic).
/// A shorter version that is a prefix of a longer one is "less"
/// (1.2 < 1.2.1), matching semver intuition.
fn lenient_compare(a: &str, b: &str) -> Option<Ordering> {
    // A "version" with no digits at all is not a version — refusing to
    // compare it is what keeps garbage bounds from becoming wildcards.
    if !a.bytes().any(|b| b.is_ascii_digit()) || !b.bytes().any(|c| c.is_ascii_digit()) {
        return None;
    }
    let sa = segments(a);
    let sb = segments(b);
    if sa.is_empty() || sb.is_empty() {
        return None;
    }

    for (x, y) in sa.iter().zip(sb.iter()) {
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(nx), Ok(ny)) => nx.cmp(&ny),
            _ => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return Some(ord);
        }
    }
    Some(sa.len().cmp(&sb.len()))
}

fn segments(v: &str) -> Vec<&str> {
    v.trim()
        .trim_start_matches('v')
        .split(['.', '-', '_', '+'])
        .filter(|s| !s.is_empty())
        .collect()
}

/// Check a version against a comma-separated constraint list
/// (`>=0.30.0,<0.30.5`). Returns:
/// - `Some(true)` — version is inside the range
/// - `Some(false)` — version is outside the range
/// - `None` — the range itself is malformed (caller should surface a
///   warning; a bad range must NOT silently match everything)
pub fn version_in_range(version: &str, range: &str) -> Option<bool> {
    for constraint in range.split(',') {
        let constraint = constraint.trim();
        if constraint.is_empty() {
            continue;
        }
        let (op, bound): (fn(Ordering) -> bool, &str) =
            if let Some(b) = constraint.strip_prefix(">=") {
                (|o| o != Ordering::Less, b)
            } else if let Some(b) = constraint.strip_prefix("<=") {
                (|o| o != Ordering::Greater, b)
            } else if let Some(b) = constraint.strip_prefix("!=") {
                (|o| o != Ordering::Equal, b)
            } else if let Some(b) = constraint.strip_prefix("==") {
                (|o| o == Ordering::Equal, b)
            } else if let Some(b) = constraint.strip_prefix('>') {
                (|o| o == Ordering::Greater, b)
            } else if let Some(b) = constraint.strip_prefix('<') {
                (|o| o == Ordering::Less, b)
            } else {
                // No recognized operator — malformed range
                return None;
            };

        let bound = bound.trim();
        match compare(version, bound) {
            Some(ord) => {
                if !op(ord) {
                    return Some(false);
                }
            }
            // Bound is garbage — malformed range, fail safe
            None => return None,
        }
    }
    Some(true)
}

/// Validate a range expression without a version (used at indicator load
/// time so malformed ranges surface immediately instead of at match time).
pub fn validate_range(range: &str) -> bool {
    version_in_range("0.0.0", range).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_basics() {
        assert_eq!(compare("1.2.3", "1.2.4"), Some(Ordering::Less));
        assert_eq!(compare("2.0.0", "1.9.9"), Some(Ordering::Greater));
        assert_eq!(compare("1.0.0", "1.0.0"), Some(Ordering::Equal));
    }

    #[test]
    fn lenient_pip_and_go() {
        // PEP 440 two-segment versions (not semver)
        assert_eq!(compare("1.2", "1.3"), Some(Ordering::Less));
        assert_eq!(compare("1.2", "1.2.1"), Some(Ordering::Less));
        // Go-style leading v
        assert_eq!(compare("v1.2.3", "1.2.3"), Some(Ordering::Equal));
        // Four-segment versions
        assert_eq!(compare("1.2.3.4", "1.2.3.5"), Some(Ordering::Less));
        // post-releases compare by suffix
        assert_eq!(compare("2.0", "2.0.post1"), Some(Ordering::Less));
    }

    #[test]
    fn range_matching() {
        assert_eq!(version_in_range("0.30.2", ">=0.30.0,<0.30.5"), Some(true));
        assert_eq!(version_in_range("0.30.0", ">=0.30.0,<0.30.5"), Some(true));
        assert_eq!(version_in_range("0.30.5", ">=0.30.0,<0.30.5"), Some(false));
        assert_eq!(version_in_range("0.29.0", ">=0.30.0,<0.30.5"), Some(false));
        assert_eq!(version_in_range("1.0.0", ">=0.30.0,<0.30.5"), Some(false));
    }

    #[test]
    fn range_matching_non_semver() {
        // pip-style versions now work in ranges (previously always false)
        assert_eq!(version_in_range("1.2", ">=1.0,<2.0"), Some(true));
        assert_eq!(version_in_range("2.1", ">=1.0,<2.0"), Some(false));
    }

    #[test]
    fn malformed_range_is_not_a_wildcard() {
        // Previously a range with unparseable bounds matched EVERY version.
        assert_eq!(version_in_range("1.0.0", "banana"), None);
        assert_eq!(version_in_range("1.0.0", ">=banana"), None);
        assert!(!validate_range("~=1.0")); // unsupported operator
        assert!(validate_range(">=0.30.0,<0.30.5"));
    }
}
