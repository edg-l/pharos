//! Pure math / misc helpers from `specs/phase0/beacon-chain.md` "Math" and
//! "Misc" sections.

use pharos_utils::Hash256;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const UINT64_MAX: u64 = u64::MAX;
/// Pre-computed floor(sqrt(2^64 - 1)).  Per `specs/phase0/beacon-chain.md:189`.
pub const UINT64_MAX_SQRT: u64 = 4_294_967_295;

// ── Math helpers ──────────────────────────────────────────────────────────────

/// Return the largest integer `x` such that `x * x <= n`.
///
/// Per `specs/phase0/beacon-chain.md:626-637`.
#[allow(clippy::manual_div_ceil)]
pub fn integer_squareroot(n: u64) -> u64 {
    if n == UINT64_MAX {
        return UINT64_MAX_SQRT;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// XOR two 32-byte strings byte-by-byte.
///
/// Per `specs/phase0/beacon-chain.md:643-647`.
pub fn xor(a: &Hash256, b: &Hash256) -> Hash256 {
    let mut out = [0u8; 32];
    for (i, (ai, bi)) in a.as_slice().iter().zip(b.as_slice().iter()).enumerate() {
        out[i] = ai ^ bi;
    }
    Hash256::from_array(out)
}

/// Deserialize 8 bytes (little-endian) into a `u64`.
///
/// Per `specs/phase0/beacon-chain.md:659-663`.
pub fn bytes_to_uint64(data: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    let len = data.len().min(8);
    arr[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(arr)
}

/// Serialize a `u64` to 8 bytes (little-endian).
///
/// Per `specs/phase0/beacon-chain.md:651-654`.
pub fn uint_to_bytes(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

// ── Constants used by accessors ───────────────────────────────────────────────

/// `FAR_FUTURE_EPOCH` per `specs/phase0/beacon-chain.md:192`.
pub const FAR_FUTURE_EPOCH: u64 = u64::MAX;

/// `GENESIS_EPOCH` per `specs/phase0/beacon-chain.md:191`.
pub const GENESIS_EPOCH: u64 = 0;

/// `MIN_PER_EPOCH_CHURN_LIMIT` per `specs/phase0/beacon-chain.md:348`.
///
/// NOTE: The actual value is preset-specific (mainnet=4, minimal=2) and lives in
/// `EthSpec::MIN_PER_EPOCH_CHURN_LIMIT`. This constant retains the mainnet value
/// for legacy reference only; use `E::MIN_PER_EPOCH_CHURN_LIMIT` in STF code.
#[allow(dead_code)]
pub const MIN_PER_EPOCH_CHURN_LIMIT: u64 = 4;

/// `CHURN_LIMIT_QUOTIENT` per `specs/phase0/beacon-chain.md:349`.
///
/// NOTE: The actual value is preset-specific (mainnet=65536, minimal=32) and lives in
/// `EthSpec::CHURN_LIMIT_QUOTIENT`. This constant retains the mainnet value
/// for legacy reference only; use `E::CHURN_LIMIT_QUOTIENT` in STF code.
#[allow(dead_code)]
pub const CHURN_LIMIT_QUOTIENT: u64 = 65_536;

// Domain type bytes per `specs/phase0/beacon-chain.md:209-215`.
pub const DOMAIN_BEACON_PROPOSER: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
pub const DOMAIN_BEACON_ATTESTER: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
pub const DOMAIN_RANDAO: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
pub const DOMAIN_DEPOSIT: [u8; 4] = [0x03, 0x00, 0x00, 0x00];
pub const DOMAIN_VOLUNTARY_EXIT: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_squareroot_table() {
        let cases: &[(u64, u64)] = &[
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 2),
            (8, 2),
            (9, 3),
            (15, 3),
            (16, 4),
            (100, 10),
            (u64::MAX, UINT64_MAX_SQRT),
        ];
        for &(n, expected) in cases {
            let got = integer_squareroot(n);
            assert_eq!(got, expected, "integer_squareroot({n})");
            // Verify property: got^2 <= n < (got+1)^2
            if n < u64::MAX {
                assert!(got * got <= n);
                assert!((got + 1).saturating_mul(got + 1) > n);
            }
        }
    }

    #[test]
    fn xor_known() {
        let a = Hash256::from_array([0xAA; 32]);
        let b = Hash256::from_array([0x55; 32]);
        let result = xor(&a, &b);
        assert_eq!(result, Hash256::from_array([0xFF; 32]));
    }

    #[test]
    fn xor_identity() {
        let a = Hash256::from_array([0x12; 32]);
        let zero = Hash256::from_array([0x00; 32]);
        assert_eq!(xor(&a, &zero), a);
    }

    #[test]
    fn bytes_to_uint64_little_endian() {
        let cases: &[(&[u8], u64)] = &[
            (&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 1),
            (&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 256),
            (&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], u64::MAX),
            (&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0),
        ];
        for &(bytes, expected) in cases {
            assert_eq!(bytes_to_uint64(bytes), expected);
        }
    }

    #[test]
    fn uint_to_bytes_round_trip() {
        let cases: &[u64] = &[0, 1, 256, u64::MAX, 0xDEAD_BEEF_CAFE_BABE];
        for &n in cases {
            let bytes = uint_to_bytes(n);
            assert_eq!(bytes_to_uint64(&bytes), n);
        }
    }
}
