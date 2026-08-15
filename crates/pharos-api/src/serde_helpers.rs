//! In-house serde helpers for the Beacon API JSON wire format.
//!
//! Beacon API JSON encoding rules:
//! - Integers are quoted decimal strings (`"slot": "10"`).
//! - Byte arrays / roots / pubkeys are `0x`-prefixed lowercase hex.
//!
//! Neither rule is compatible with the stdlib `serde` defaults, and
//! `ethereum_serde_utils` is a rejected dep, so these are in-house.
//!
//! # Usage for fixed-size byte arrays
//!
//! Use the free-function pairs with `#[serde(serialize_with = ..., deserialize_with = ...)]`:
//!
//! ```ignore
//! #[serde(serialize_with = "serialize_hex32", deserialize_with = "deserialize_hex32")]
//! root: [u8; 32],
//!
//! #[serde(serialize_with = "serialize_hex4", deserialize_with = "deserialize_hex4")]
//! fork_version: [u8; 4],
//! ```
//!
//! Available pairs: `serialize_hex4`/`deserialize_hex4`, `serialize_hex32`/`deserialize_hex32`,
//! `serialize_hex48`/`deserialize_hex48`, `serialize_hex96`/`deserialize_hex96`.
//!
//! For `Vec<u8>` fields use `#[serde(with = "hex_bytes")]`.

// ── quoted_int ────────────────────────────────────────────────────────────────

/// Serde module: `u64` ↔ quoted decimal string (e.g. `"42"`).
///
/// Use as `#[serde(with = "crate::serde_helpers::quoted_u64")]`.
pub mod quoted_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse::<u64>().map_err(serde::de::Error::custom)
    }
}

// ── hex_bytes ─────────────────────────────────────────────────────────────────

/// Serde module: `Vec<u8>` ↔ `0x`-prefixed lowercase hex string.
///
/// Use as `#[serde(with = "crate::serde_helpers::hex_bytes")]`.
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(2 + v.len() * 2);
        out.push_str("0x");
        for b in v {
            use std::fmt::Write as _;
            write!(out, "{b:02x}").unwrap();
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let hex = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(hex).map_err(serde::de::Error::custom)
    }
}

// ── Free-function pairs for common fixed sizes ────────────────────────────────
//
// Use with `#[serde(serialize_with = "...", deserialize_with = "...")]`.
// These avoid the `[u8; N]` ↔ `with`-module incompatibility that arises
// because serde `with` modules receive `&T` but const-generic arrays need
// a concrete size at the serialize site.

/// Serialize a `[u8; 4]` as `0x`-prefixed lowercase hex (fork version).
pub fn serialize_hex4<S: serde::Serializer>(v: &[u8; 4], s: S) -> Result<S::Ok, S::Error> {
    hex_bytes::serialize(v.as_slice(), s)
}

/// Deserialize a `0x`-hex string into a `[u8; 4]`.
pub fn deserialize_hex4<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 4], D::Error> {
    let v: Vec<u8> = hex_bytes::deserialize(d)?;
    v.try_into()
        .map_err(|_| serde::de::Error::custom("expected exactly 4 bytes"))
}

/// Serialize a `[u8; 32]` as `0x`-prefixed lowercase hex (root / hash).
pub fn serialize_hex32<S: serde::Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    hex_bytes::serialize(v.as_slice(), s)
}

/// Deserialize a `0x`-hex string into a `[u8; 32]`.
pub fn deserialize_hex32<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let v: Vec<u8> = hex_bytes::deserialize(d)?;
    v.try_into()
        .map_err(|_| serde::de::Error::custom("expected exactly 32 bytes"))
}

/// Serialize a `[u8; 48]` as `0x`-prefixed lowercase hex (BLS pubkey).
pub fn serialize_hex48<S: serde::Serializer>(v: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
    hex_bytes::serialize(v.as_slice(), s)
}

/// Deserialize a `0x`-hex string into a `[u8; 48]`.
pub fn deserialize_hex48<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
    let v: Vec<u8> = hex_bytes::deserialize(d)?;
    v.try_into()
        .map_err(|_| serde::de::Error::custom("expected exactly 48 bytes"))
}

/// Serialize a `[u8; 20]` as `0x`-prefixed lowercase hex (Ethereum execution address).
pub fn serialize_hex20<S: serde::Serializer>(v: &[u8; 20], s: S) -> Result<S::Ok, S::Error> {
    hex_bytes::serialize(v.as_slice(), s)
}

/// Deserialize a `0x`-hex string into a `[u8; 20]`.
pub fn deserialize_hex20<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 20], D::Error> {
    let v: Vec<u8> = hex_bytes::deserialize(d)?;
    v.try_into()
        .map_err(|_| serde::de::Error::custom("expected exactly 20 bytes"))
}

/// Serialize a `[u8; 96]` as `0x`-prefixed lowercase hex (BLS signature).
pub fn serialize_hex96<S: serde::Serializer>(v: &[u8; 96], s: S) -> Result<S::Ok, S::Error> {
    hex_bytes::serialize(v.as_slice(), s)
}

/// Deserialize a `0x`-hex string into a `[u8; 96]`.
pub fn deserialize_hex96<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 96], D::Error> {
    let v: Vec<u8> = hex_bytes::deserialize(d)?;
    v.try_into()
        .map_err(|_| serde::de::Error::custom("expected exactly 96 bytes"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    // ── u64 round-trip ────────────────────────────────────────────────────────

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct WithU64 {
        #[serde(with = "quoted_u64")]
        value: u64,
    }

    #[test]
    fn u64_zero_round_trip() {
        let orig = WithU64 { value: 0 };
        let json = serde_json::to_string(&orig).unwrap();
        assert_eq!(json, r#"{"value":"0"}"#);
        let back: WithU64 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn u64_max_round_trip() {
        let orig = WithU64 { value: u64::MAX };
        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.contains("18446744073709551615"));
        let back: WithU64 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn u64_typical_slot_round_trip() {
        let orig = WithU64 { value: 42 };
        let json = serde_json::to_string(&orig).unwrap();
        assert_eq!(json, r#"{"value":"42"}"#);
        let back: WithU64 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    // ── [u8; 32] round-trip ───────────────────────────────────────────────────

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct WithRoot {
        #[serde(
            serialize_with = "serialize_hex32",
            deserialize_with = "deserialize_hex32"
        )]
        root: [u8; 32],
    }

    #[test]
    fn fixed32_zero_round_trip() {
        let orig = WithRoot { root: [0u8; 32] };
        let json = serde_json::to_string(&orig).unwrap();
        assert!(
            json.contains("0x0000000000000000000000000000000000000000000000000000000000000000")
        );
        let back: WithRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn fixed32_nonzero_round_trip() {
        let mut root = [0u8; 32];
        root[0] = 0xde;
        root[31] = 0xad;
        let orig = WithRoot { root };
        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.starts_with(r#"{"root":"0xde"#));
        let back: WithRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    // ── Vec<u8> round-trip ────────────────────────────────────────────────────

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct WithVec {
        #[serde(with = "hex_bytes")]
        data: Vec<u8>,
    }

    #[test]
    fn vec_empty_round_trip() {
        let orig = WithVec { data: vec![] };
        let json = serde_json::to_string(&orig).unwrap();
        assert_eq!(json, r#"{"data":"0x"}"#);
        let back: WithVec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn vec_bytes_round_trip() {
        let orig = WithVec {
            data: vec![0xca, 0xfe, 0xba, 0xbe],
        };
        let json = serde_json::to_string(&orig).unwrap();
        assert_eq!(json, r#"{"data":"0xcafebabe"}"#);
        let back: WithVec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn hex_prefix_optional_on_deserialize() {
        // Deserializer accepts both "0xcafe" and "cafe".
        let with_prefix: WithVec = serde_json::from_str(r#"{"data":"0xcafe"}"#).unwrap();
        let without_prefix: WithVec = serde_json::from_str(r#"{"data":"cafe"}"#).unwrap();
        assert_eq!(with_prefix, without_prefix);
    }

    // ── [u8; 4] round-trip (fork version) ────────────────────────────────────

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct WithFork {
        #[serde(
            serialize_with = "serialize_hex4",
            deserialize_with = "deserialize_hex4"
        )]
        version: [u8; 4],
    }

    #[test]
    fn fixed4_zero_round_trip() {
        let orig = WithFork { version: [0u8; 4] };
        let json = serde_json::to_string(&orig).unwrap();
        assert_eq!(json, r#"{"version":"0x00000000"}"#);
        let back: WithFork = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn fixed4_nonzero_round_trip() {
        let orig = WithFork {
            version: [0x01, 0x00, 0x00, 0x00],
        };
        let json = serde_json::to_string(&orig).unwrap();
        assert_eq!(json, r#"{"version":"0x01000000"}"#);
        let back: WithFork = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    // ── [u8; 48] round-trip (BLS pubkey) ─────────────────────────────────────

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct WithPubkey {
        #[serde(
            serialize_with = "serialize_hex48",
            deserialize_with = "deserialize_hex48"
        )]
        pubkey: [u8; 48],
    }

    #[test]
    fn fixed48_zero_round_trip() {
        let orig = WithPubkey { pubkey: [0u8; 48] };
        let json = serde_json::to_string(&orig).unwrap();
        let s = json.as_str();
        assert!(s.contains("\"0x"));
        // 2 (0x) + 96 hex chars = 98 chars inside quotes
        assert!(s.contains(&"0".repeat(96)));
        let back: WithPubkey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn fixed48_nonzero_round_trip() {
        let mut pubkey = [0u8; 48];
        pubkey[0] = 0xab;
        pubkey[47] = 0xcd;
        let orig = WithPubkey { pubkey };
        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.contains("\"0xab"));
        let back: WithPubkey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    // ── [u8; 20] round-trip (execution address) ───────────────────────────────

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct WithAddr {
        #[serde(
            serialize_with = "serialize_hex20",
            deserialize_with = "deserialize_hex20"
        )]
        addr: [u8; 20],
    }

    #[test]
    fn fixed20_zero_round_trip() {
        let orig = WithAddr { addr: [0u8; 20] };
        let json = serde_json::to_string(&orig).unwrap();
        assert_eq!(
            json,
            r#"{"addr":"0x0000000000000000000000000000000000000000"}"#
        );
        let back: WithAddr = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn fixed20_nonzero_round_trip() {
        let mut addr = [0u8; 20];
        addr[0] = 0xab;
        addr[19] = 0xcd;
        let orig = WithAddr { addr };
        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.contains("\"0xab"));
        let back: WithAddr = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    // ── [u8; 96] round-trip (BLS signature) ──────────────────────────────────

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct WithSig {
        #[serde(
            serialize_with = "serialize_hex96",
            deserialize_with = "deserialize_hex96"
        )]
        sig: [u8; 96],
    }

    #[test]
    fn fixed96_zero_round_trip() {
        let orig = WithSig { sig: [0u8; 96] };
        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.contains("\"0x"));
        // 2 (0x) + 192 hex chars
        assert!(json.contains(&"0".repeat(192)));
        let back: WithSig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn fixed96_nonzero_round_trip() {
        let mut sig = [0u8; 96];
        sig[0] = 0xde;
        sig[95] = 0xad;
        let orig = WithSig { sig };
        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.contains("\"0xde"));
        let back: WithSig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, orig);
    }
}
