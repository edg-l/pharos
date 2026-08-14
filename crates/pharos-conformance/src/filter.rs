//! Filter for selecting which test categories to run.

/// Filter used to select which spec tests to run.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    /// If set, only run tests for this fork (e.g. `phase0`).
    pub fork: Option<String>,
    /// If set, only run tests in this category (e.g. `ssz_generic`).
    pub category: Option<String>,
    /// If set, only run tests for this preset (e.g. `mainnet`).
    pub preset: Option<String>,
}

impl Filter {
    /// Returns `true` if the given (fork, category, preset) combination passes the filter.
    pub fn matches(&self, fork: &str, category: &str, preset: &str) -> bool {
        if let Some(f) = &self.fork {
            if f != fork {
                return false;
            }
        }
        if let Some(c) = &self.category {
            if c != category {
                return false;
            }
        }
        if let Some(p) = &self.preset {
            if p != preset && preset != "-" {
                return false;
            }
        }
        true
    }
}
