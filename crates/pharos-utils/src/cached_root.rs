//! `CachedRoot` — lazily-populated `Hash256` cache with transparent derives.
//!
//! Custom `Clone` resets the cache (mirrors `Validator::clone`
//! reset semantic that prevents stale roots after clone-mutate patterns).
//! Custom `PartialEq` always returns `true` so the field is invisible to
//! struct-wide `#[derive(PartialEq, Eq)]` comparisons. Combined with
//! `#[ssz(skip)]` (which excludes the field from SSZ Encode/Decode/TreeHash
//! emissions), this lets a container add a Merkle-root cache without
//! touching its derived traits.

use std::sync::OnceLock;

use crate::Hash256;

#[derive(Default, Debug)]
pub struct CachedRoot(OnceLock<Hash256>);

impl CachedRoot {
    /// Return the cached root, computing it via `f` on first call.
    pub fn get_or_init<F: FnOnce() -> Hash256>(&self, f: F) -> Hash256 {
        *self.0.get_or_init(f)
    }

    /// Clear the cache. The next `get_or_init` call will recompute.
    pub fn invalidate(&mut self) {
        self.0.take();
    }

    /// Whether the cache has been populated since the last invalidation.
    pub fn is_populated(&self) -> bool {
        self.0.get().is_some()
    }
}

impl Clone for CachedRoot {
    /// Cloning always yields an EMPTY cache; the parent's cached value does
    /// NOT propagate. This is the safety property: after `let s2 = s.clone();
    /// s2.field = X;` the cache on `s2` is correctly empty and the next
    /// `cached_tree_hash_root()` call computes a fresh root from the mutated
    /// state. Without this, the clone would carry the pre-mutation root and
    /// silently report stale data (the `validator_clone_carries_cache`
    /// bug that introduced 215 conformance failures).
    fn clone(&self) -> Self {
        Self(OnceLock::new())
    }
}

impl PartialEq for CachedRoot {
    /// Always equal: the cache is a derived value, not part of identity. Two
    /// containers with identical wire content but different cache populations
    /// are equal at the spec level.
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CachedRoot {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_resets_cache() {
        let a = CachedRoot::default();
        let _ = a.get_or_init(|| Hash256::from_array([1; 32]));
        assert!(a.is_populated());

        let b = a.clone();
        assert!(!b.is_populated(), "clone must produce an empty cache");
    }

    #[test]
    fn eq_ignores_cache_state() {
        let a = CachedRoot::default();
        let b = CachedRoot::default();
        let _ = a.get_or_init(|| Hash256::from_array([1; 32]));
        assert!(a.is_populated());
        assert!(!b.is_populated());
        assert_eq!(a, b, "PartialEq must ignore cache population state");
    }

    #[test]
    fn invalidate_clears() {
        let mut a = CachedRoot::default();
        let _ = a.get_or_init(|| Hash256::from_array([1; 32]));
        a.invalidate();
        assert!(!a.is_populated());
    }
}
