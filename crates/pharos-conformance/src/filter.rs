//! Filter for selecting which test categories to run.

/// A single `fork[/category[/preset]]` pattern from `--filter`.
#[derive(Debug, Clone)]
pub struct FilterPattern {
    pub fork: String,
    pub category: Option<String>,
    pub preset: Option<String>,
}

/// Filter used to select which spec tests to run.
///
/// Populated either from the legacy `--fork`/`--category`/`--preset` flags or
/// from the `--filter` flag. The two modes are mutually exclusive.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    /// If set, only run tests for this fork (e.g. `phase0`).
    /// Legacy field; kept for callers that still read it directly.
    pub fork: Option<String>,
    /// If set, only run tests in this category (e.g. `ssz_generic`).
    /// Legacy field; kept for callers that still read it directly.
    pub category: Option<String>,
    /// If set, only run tests for this preset (e.g. `mainnet`).
    /// Legacy field; kept for callers that still read it directly.
    pub preset: Option<String>,
    /// Parsed patterns. One entry when populated from `--fork/--category/--preset`;
    /// N entries when populated from `--filter`. Empty means "no filter".
    pub patterns: Vec<FilterPattern>,
}

impl Filter {
    /// Returns `true` if the given `(fork, category, preset)` passes the filter.
    ///
    /// When `patterns` is empty, every row passes (no filter active).
    /// When non-empty, at least one pattern must match (logical OR).
    /// A pattern matches when its segments equal the row's segments left-to-right;
    /// an absent `category` or `preset` on the pattern matches any value.
    pub fn matches(&self, fork: &str, category: &str, preset: &str) -> bool {
        if self.patterns.is_empty() {
            return true; // no filter set
        }
        self.patterns.iter().any(|p| {
            p.fork == fork
                && p.category.as_deref().is_none_or(|c| c == category)
                && p.preset
                    .as_deref()
                    .is_none_or(|p| p == preset || preset == "-")
        })
    }
}

/// Parse a `--filter` value (comma-separated `fork[/category[/preset]]` patterns).
///
/// Returns a `Vec<FilterPattern>` on success, or an error string describing the
/// first malformed pattern. Error strings have the form:
/// `invalid --filter pattern '<offending>': <reason>`.
///
/// A pattern is malformed if it:
/// - has zero segments after splitting on `/`
/// - has more than 3 segments
/// - has any empty segment (catches `phase0//operations`, leading `/`, trailing `/`)
pub fn parse_filter_patterns(value: &str) -> Result<Vec<FilterPattern>, String> {
    let mut patterns = Vec::new();
    for raw in value.split(',') {
        let segments: Vec<&str> = raw.split('/').collect();
        if segments.is_empty() || (segments.len() == 1 && segments[0].is_empty()) {
            return Err(format!(
                "invalid --filter pattern '{raw}': must have at least one segment"
            ));
        }
        if segments.len() > 3 {
            return Err(format!(
                "invalid --filter pattern '{raw}': too many segments (max 3: fork/category/preset)"
            ));
        }
        for seg in &segments {
            if seg.is_empty() {
                return Err(format!("invalid --filter pattern '{raw}': empty segment"));
            }
        }
        patterns.push(FilterPattern {
            fork: segments[0].to_string(),
            category: segments.get(1).map(|s| s.to_string()),
            preset: segments.get(2).map(|s| s.to_string()),
        });
    }
    Ok(patterns)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(filter: &Filter, fork: &str, cat: &str, preset: &str) -> bool {
        filter.matches(fork, cat, preset)
    }

    fn make_filter(patterns: Vec<FilterPattern>) -> Filter {
        Filter {
            patterns,
            ..Filter::default()
        }
    }

    // --- parse_filter_patterns tests ---

    #[test]
    fn parse_phase0() {
        let patterns = parse_filter_patterns("phase0").unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].fork, "phase0");
        assert!(patterns[0].category.is_none());
        assert!(patterns[0].preset.is_none());
    }

    #[test]
    fn parse_phase0_operations() {
        let patterns = parse_filter_patterns("phase0/operations").unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].fork, "phase0");
        assert_eq!(patterns[0].category.as_deref(), Some("operations"));
        assert!(patterns[0].preset.is_none());
    }

    #[test]
    fn parse_phase0_operations_mainnet() {
        let patterns = parse_filter_patterns("phase0/operations/mainnet").unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].fork, "phase0");
        assert_eq!(patterns[0].category.as_deref(), Some("operations"));
        assert_eq!(patterns[0].preset.as_deref(), Some("mainnet"));
    }

    #[test]
    fn parse_multi_pattern() {
        let patterns = parse_filter_patterns("phase0,altair/fork_choice").unwrap();
        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0].fork, "phase0");
        assert!(patterns[0].category.is_none());
        assert_eq!(patterns[1].fork, "altair");
        assert_eq!(patterns[1].category.as_deref(), Some("fork_choice"));
    }

    #[test]
    fn reject_double_slash() {
        let err = parse_filter_patterns("phase0//operations").unwrap_err();
        assert!(err.contains("phase0//operations"), "got: {err}");
        assert!(err.contains("empty segment"), "got: {err}");
    }

    #[test]
    fn reject_leading_slash() {
        let err = parse_filter_patterns("/phase0").unwrap_err();
        assert!(err.contains("/phase0"), "got: {err}");
        assert!(err.contains("empty segment"), "got: {err}");
    }

    #[test]
    fn reject_trailing_slash() {
        let err = parse_filter_patterns("phase0/operations/").unwrap_err();
        assert!(err.contains("phase0/operations/"), "got: {err}");
        assert!(err.contains("empty segment"), "got: {err}");
    }

    #[test]
    fn reject_too_many_segments() {
        let err = parse_filter_patterns("a/b/c/d").unwrap_err();
        assert!(err.contains("a/b/c/d"), "got: {err}");
        assert!(err.contains("too many segments"), "got: {err}");
    }

    #[test]
    fn reject_empty_input() {
        let err = parse_filter_patterns("").unwrap_err();
        assert!(err.contains("at least one segment"), "got: {err}");
    }

    // --- Filter::matches tests ---

    #[test]
    fn empty_patterns_passes_all() {
        let filter = Filter::default();
        assert!(matches(&filter, "phase0", "ssz_generic", "-"));
        assert!(matches(&filter, "altair", "anything", "mainnet"));
    }

    #[test]
    fn fork_only_pattern() {
        let filter = make_filter(parse_filter_patterns("phase0").unwrap());
        assert!(matches(&filter, "phase0", "ssz_generic", "-"));
        assert!(matches(&filter, "phase0", "ssz_static", "mainnet"));
        assert!(!matches(&filter, "altair", "ssz_static", "mainnet"));
    }

    #[test]
    fn fork_category_pattern() {
        let filter = make_filter(parse_filter_patterns("phase0/operations").unwrap());
        assert!(matches(&filter, "phase0", "operations", "-"));
        assert!(matches(&filter, "phase0", "operations", "mainnet"));
        assert!(!matches(&filter, "phase0", "ssz_generic", "-"));
    }

    #[test]
    fn fork_category_preset_pattern() {
        let filter = make_filter(parse_filter_patterns("phase0/ssz_static/mainnet").unwrap());
        assert!(matches(&filter, "phase0", "ssz_static", "mainnet"));
        assert!(!matches(&filter, "phase0", "ssz_static", "minimal"));
    }

    #[test]
    fn dash_preset_matches_preset_none() {
        // A fork-only pattern should match rows with preset "-" (preset-less rows).
        let filter = make_filter(parse_filter_patterns("phase0").unwrap());
        assert!(matches(&filter, "phase0", "ssz_generic", "-"));
    }

    #[test]
    fn multi_pattern_or() {
        let filter = make_filter(parse_filter_patterns("phase0,altair/fork_choice").unwrap());
        assert!(matches(&filter, "phase0", "ssz_generic", "-"));
        assert!(matches(&filter, "altair", "fork_choice", "-"));
        assert!(!matches(&filter, "altair", "ssz_static", "mainnet"));
    }
}
