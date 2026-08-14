//! SHA-256 hash wrappers.
//!
//! Uses [`sha2::Sha256`] from the `sha2` crate. SHA-NI (x86_64) and ARMv8
//! crypto extensions are selected automatically at runtime by `sha2`'s
//! internal `cpufeatures` integration — no feature gate or compile-time
//! configuration is needed (B1 resolution).

use sha2::{Digest, Sha256};

use crate::bytes::Hash256;

/// Computes the SHA-256 digest of `input`.
pub fn hash(input: &[u8]) -> Hash256 {
    let digest = Sha256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Hash256::from_array(out)
}

/// Computes the SHA-256 digest of the concatenation of `a` and `b` without
/// allocating an intermediate buffer.
pub fn hash_concat(a: &[u8], b: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Hash256::from_array(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256("") from FIPS 180-4.
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// SHA-256("abc") from FIPS 180-4.
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn hash_empty_known_answer() {
        let result = hash(b"");
        let expected: Hash256 = SHA256_EMPTY.parse().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn hash_abc_known_answer() {
        let result = hash(b"abc");
        let expected: Hash256 = SHA256_ABC.parse().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn hash_concat_equals_hash_joined() {
        let a = b"hello";
        let b = b"world";
        let concat_result = hash_concat(a, b);
        let mut joined = Vec::new();
        joined.extend_from_slice(a);
        joined.extend_from_slice(b);
        let joined_result = hash(joined.as_slice());
        assert_eq!(concat_result, joined_result);
    }
}
