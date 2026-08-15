//! 256-bit unsigned integer with little-endian byte storage matching the SSZ
//! wire format.
//!
//! In-house implementation; no external bigint dependency (Q3 resolution:
//! in-house mandatory per CLAUDE.md / m0-plan.md).
//!
//! Operations implemented: `Add`, `Sub`, `Eq`, `Ord`, `Display` (decimal),
//! `Debug`, `From<u64>`, `From<u128>`, `to_le_bytes`, `from_le_bytes`.
//!
//! `Mul` is explicitly not implemented in M0; arithmetic needs are limited
//! to `Add`, `Sub`, and comparison. `Mul` can be added in a later milestone
//! if required.

use std::fmt;
use std::ops::{Add, Sub};
use std::str::FromStr;

/// A 256-bit unsigned integer stored in little-endian byte order.
///
/// The internal representation is `[u8; 32]` where byte 0 is the least
/// significant byte, matching the SSZ `uint256` wire format.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uint256([u8; 32]);

/// Decompose a `Uint256` into four `u64` limbs (little-endian: limb 0 is
/// least significant).
fn to_limbs(n: &Uint256) -> [u64; 4] {
    let b = &n.0;
    [
        u64::from_le_bytes(b[0..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
        u64::from_le_bytes(b[16..24].try_into().unwrap()),
        u64::from_le_bytes(b[24..32].try_into().unwrap()),
    ]
}

/// Compute `a - b` using limb-by-limb subtraction with borrow propagation.
/// Extracted to a free function to avoid triggering `clippy::suspicious_arithmetic_impl`
/// (which fires when `+` appears inside a `Sub` impl body).
fn wrapping_sub(a: Uint256, b: Uint256) -> Uint256 {
    let al = to_limbs(&a);
    let bl = to_limbs(&b);
    let mut result = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (diff, b1) = al[i].overflowing_sub(bl[i]);
        let (diff, b2) = diff.overflowing_sub(borrow);
        result[i] = diff;
        // b1 and b2 cannot both be true simultaneously (total borrow ≤ 1).
        borrow = u64::from(b1) | u64::from(b2);
    }
    from_limbs(result)
}

/// Compose a `Uint256` from four little-endian `u64` limbs.
fn from_limbs(limbs: [u64; 4]) -> Uint256 {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&limbs[0].to_le_bytes());
    bytes[8..16].copy_from_slice(&limbs[1].to_le_bytes());
    bytes[16..24].copy_from_slice(&limbs[2].to_le_bytes());
    bytes[24..32].copy_from_slice(&limbs[3].to_le_bytes());
    Uint256(bytes)
}

impl Uint256 {
    /// The zero value.
    pub const ZERO: Uint256 = Uint256([0u8; 32]);

    /// Returns the value as a little-endian 32-byte array (SSZ wire format).
    pub fn to_le_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Constructs a `Uint256` from a little-endian 32-byte array.
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<u64> for Uint256 {
    fn from(v: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&v.to_le_bytes());
        Self(bytes)
    }
}

impl FromStr for Uint256 {
    type Err = String;

    /// Parse a decimal or `0x`-prefixed hex string into a `Uint256`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            // Hex: parse up to 64 hex digits.
            if hex.len() > 64 {
                return Err(format!("hex value too large for Uint256: {s}"));
            }
            let mut bytes = [0u8; 32];
            // Pad to even length.
            let padded = if hex.len() % 2 != 0 {
                format!("0{hex}")
            } else {
                hex.to_string()
            };
            // Decode big-endian hex into the high bytes, then reverse into LE.
            let decoded = (0..padded.len() / 2)
                .map(|i| u8::from_str_radix(&padded[2 * i..2 * i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| format!("invalid hex in Uint256: {s}"))?;
            // Copy decoded (big-endian) into the tail of a 32-byte buffer, then reverse.
            let offset = 32 - decoded.len();
            bytes[offset..].copy_from_slice(&decoded);
            bytes.reverse(); // big-endian → little-endian
            Ok(Uint256(bytes))
        } else {
            let mut result = Uint256::ZERO;
            for ch in s.chars() {
                let digit = ch
                    .to_digit(10)
                    .ok_or_else(|| format!("invalid decimal digit '{ch}' in Uint256: {s}"))?;
                result = mul10(result);
                result = result + Uint256::from(digit as u64);
            }
            Ok(result)
        }
    }
}

/// Multiply a `Uint256` by 10 using limb-level arithmetic.
fn mul10(n: Uint256) -> Uint256 {
    let limbs = to_limbs(&n);
    let mut result = [0u64; 4];
    let mut carry: u64 = 0;
    for i in 0..4 {
        let prod = (limbs[i] as u128) * 10 + (carry as u128);
        result[i] = prod as u64;
        carry = (prod >> 64) as u64;
    }
    // Overflow (carry != 0) wraps silently, matching the wrapping contract of Add/Sub.
    from_limbs(result)
}

impl From<u128> for Uint256 {
    fn from(v: u128) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..16].copy_from_slice(&v.to_le_bytes());
        Self(bytes)
    }
}

impl Add for Uint256 {
    type Output = Self;

    /// Wrapping addition (256-bit overflow wraps to 0).
    fn add(self, rhs: Self) -> Self {
        let a = to_limbs(&self);
        let b = to_limbs(&rhs);
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum, c1) = a[i].overflowing_add(b[i]);
            let (sum, c2) = sum.overflowing_add(carry);
            result[i] = sum;
            // c1 and c2 are mutually exclusive: if c1 fired, sum is at most
            // u64::MAX - 1, so the second overflowing_add cannot overflow.
            // The `|` (rather than `+`) makes that invariant explicit at the
            // bit level; clippy's suspicious-arithmetic-impl lint flags `|`
            // inside an Add impl, so suppress it here with the rationale.
            #[allow(clippy::suspicious_arithmetic_impl)]
            {
                carry = u64::from(c1) | u64::from(c2);
            }
        }
        from_limbs(result)
    }
}

impl Sub for Uint256 {
    type Output = Self;

    /// Wrapping subtraction (underflow wraps).
    fn sub(self, rhs: Self) -> Self {
        wrapping_sub(self, rhs)
    }
}

impl Ord for Uint256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare limbs from most significant to least significant.
        let a = to_limbs(self);
        let b = to_limbs(other);
        for i in (0..4).rev() {
            match a[i].cmp(&b[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uint256({self})")
    }
}

impl fmt::Display for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut limbs = to_limbs(self);
        if limbs == [0u64; 4] {
            return f.write_str("0");
        }

        // 2^256 - 1 has 78 decimal digits; write them into a stack buffer
        // from the right, then emit the populated suffix.
        let mut buf = [0u8; 78];
        let mut idx = buf.len();
        while limbs != [0u64; 4] {
            // Schoolbook division of the 256-bit value by 10.
            let mut remainder: u128 = 0;
            for i in (0..4).rev() {
                let cur = (remainder << 64) | (limbs[i] as u128);
                limbs[i] = (cur / 10) as u64;
                remainder = cur % 10;
            }
            idx -= 1;
            buf[idx] = (remainder as u8) + b'0';
        }

        // All bytes written are ASCII digits, so the slice is valid UTF-8.
        let s = std::str::from_utf8(&buf[idx..]).expect("ASCII digits");
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u64_roundtrip() {
        let v: u64 = 0xDEAD_BEEF_1234_5678;
        let u = Uint256::from(v);
        let bytes = u.to_le_bytes();
        assert_eq!(&bytes[0..8], &v.to_le_bytes());
        assert_eq!(&bytes[8..32], &[0u8; 24]);
    }

    #[test]
    fn from_u128_roundtrip() {
        let v: u128 = 0xDEAD_BEEF_0000_0000_CAFE_BABE_1234_5678;
        let u = Uint256::from(v);
        let bytes = u.to_le_bytes();
        assert_eq!(&bytes[0..16], &v.to_le_bytes());
        assert_eq!(&bytes[16..32], &[0u8; 16]);
    }

    #[test]
    fn add_no_carry() {
        let a = Uint256::from(100u64);
        let b = Uint256::from(200u64);
        assert_eq!(a + b, Uint256::from(300u64));
    }

    #[test]
    fn add_with_carry() {
        // u64::MAX + 1 should carry into the next limb.
        let a = Uint256::from(u64::MAX);
        let b = Uint256::from(1u64);
        let result = a + b;
        let bytes = result.to_le_bytes();
        assert_eq!(&bytes[0..8], &0u64.to_le_bytes());
        assert_eq!(&bytes[8..16], &1u64.to_le_bytes());
    }

    #[test]
    fn sub_basic() {
        let a = Uint256::from(300u64);
        let b = Uint256::from(200u64);
        assert_eq!(a - b, Uint256::from(100u64));
    }

    #[test]
    fn sub_cross_limb_borrow() {
        // 2^64 - 1 borrows from limb 1 into limb 0; result is u64::MAX.
        let a = Uint256::from(1u128 << 64);
        let b = Uint256::from(1u64);
        assert_eq!(a - b, Uint256::from(u64::MAX));
    }

    #[test]
    fn add_wraps_at_256_bits() {
        // u256::MAX + 1 wraps to 0.
        let max = Uint256::from_le_bytes([0xFF; 32]);
        assert_eq!(max + Uint256::from(1u64), Uint256::ZERO);
    }

    #[test]
    fn sub_underflows_to_max() {
        // 0 - 1 wraps to u256::MAX.
        let one = Uint256::from(1u64);
        let max = Uint256::from_le_bytes([0xFF; 32]);
        assert_eq!(Uint256::ZERO - one, max);
    }

    #[test]
    fn ordering() {
        let small = Uint256::from(1u64);
        let large = Uint256::from(1000u64);
        assert!(small < large);
        assert!(large > small);
        assert_eq!(small.cmp(&small), std::cmp::Ordering::Equal);
    }

    #[test]
    fn display_zero() {
        assert_eq!(Uint256::ZERO.to_string(), "0");
    }

    #[test]
    fn display_one() {
        assert_eq!(Uint256::from(1u64).to_string(), "1");
    }

    #[test]
    fn display_large() {
        let v = Uint256::from(1_000_000_000_000u64);
        assert_eq!(v.to_string(), "1000000000000");
    }

    #[test]
    fn from_str_decimal() {
        let v: Uint256 = "58750000000000000000000".parse().unwrap();
        assert_eq!(v.to_string(), "58750000000000000000000");
    }

    #[test]
    fn from_str_zero() {
        let v: Uint256 = "0".parse().unwrap();
        assert_eq!(v, Uint256::ZERO);
    }

    #[test]
    fn from_str_hex() {
        let v: Uint256 = "0x0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        assert_eq!(v, Uint256::ZERO);
    }

    #[test]
    fn from_str_large_decimal() {
        // minimal TTD: 115792089237316195423570985008687907853269984665640564039457584007913129638912
        let s = "115792089237316195423570985008687907853269984665640564039457584007913129638912";
        let v: Uint256 = s.parse().unwrap();
        assert_eq!(v.to_string(), s);
    }

    #[test]
    fn from_le_bytes_roundtrip() {
        let mut b = [0u8; 32];
        b[0] = 0xFF;
        b[31] = 0x01;
        let u = Uint256::from_le_bytes(b);
        assert_eq!(u.to_le_bytes(), b);
    }
}
