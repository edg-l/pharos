//! ENR construction and field accessors for the Pharos networking layer.
//!
//! Implements the `eth2`, `attnets`, `quic`, and `quic6` ENR keys defined in
//! `specs/phase0/p2p-interface.md:1654-1656` and `:1670-1672`.
//!
//! The `quic` / `quic6` keys store a `u16` port using the same RLP encoding as
//! the standard `udp` / `tcp` fields. This matches the convention used by
//! Lighthouse and other CL clients. The convention is documented under
//! Q-quic-enr in `docs/decisions.md`.

use std::net::Ipv4Addr;

use discv5::enr::{CombinedKey, CombinedPublicKey, EnrPublicKey as _};
use libp2p::Multiaddr;
use pharos_ssz::{Bitvector, Decode, Encode};
use pharos_types::phase0::ENRForkID;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;

use crate::error::NetworkError;

// ── RLP helpers ───────────────────────────────────────────────────────────────

/// Decode an RLP byte string from a raw RLP blob and return the payload bytes.
///
/// The ENR custom keys are stored as RLP-encoded byte strings. The ENR crate's
/// `get_decodable::<Vec<u8>>` decodes RLP lists, not byte strings, so we must
/// strip the RLP header manually. This function handles strings up to 55 bytes
/// (short-string form: first byte = 0x80 + len) and up to 232 bytes
/// (long-string form: first byte = 0xb7 + len_of_len).
fn rlp_decode_bytes(rlp: &[u8]) -> Option<&[u8]> {
    let first = *rlp.first()?;
    if first == 0x80 {
        // Empty byte string.
        return Some(&[]);
    }
    if first <= 0xb7 {
        // Short string: first byte is 0x80 + payload length.
        let payload_len = (first - 0x80) as usize;
        let payload = rlp.get(1..1 + payload_len)?;
        return Some(payload);
    }
    if first <= 0xbf {
        // Long string: first byte is 0xb7 + number of bytes for the length.
        let len_bytes = (first - 0xb7) as usize;
        let len_slice = rlp.get(1..1 + len_bytes)?;
        let mut payload_len = 0usize;
        for &b in len_slice {
            payload_len = payload_len * 256 + b as usize;
        }
        let payload = rlp.get(1 + len_bytes..1 + len_bytes + payload_len)?;
        return Some(payload);
    }
    None
}

/// The discv5 `Enr` type (already `Enr<CombinedKey>` via the type alias).
pub type Enr = discv5::Enr;

// ── build_local_enr ───────────────────────────────────────────────────────────

/// Build and sign a local ENR for the Pharos node.
///
/// Sets the `eth2`, `attnets`, and (if provided) `quic` / `quic6` custom ENR
/// keys. Standard `ip`, `tcp`, and `udp` fields are set when the corresponding
/// optional arguments are `Some`.
///
/// `eth2`  = SSZ-encoded `ENRForkID` (16 bytes).
/// `attnets` = SSZ-encoded `Bitvector<ATTESTATION_SUBNET_COUNT>` (8 bytes).
/// `quic`  = RLP-encoded `u16` (IPv4 QUIC UDP port).
/// `quic6` = RLP-encoded `u16` (IPv6 QUIC UDP port).
///
/// Spec: `specs/phase0/p2p-interface.md:1654-1656` and `:1670-1672`.
#[allow(clippy::too_many_arguments)]
pub fn build_local_enr(
    secret_key: &CombinedKey,
    ip4: Option<Ipv4Addr>,
    udp4: Option<u16>,
    tcp4: Option<u16>,
    quic_port: Option<u16>,
    quic6_port: Option<u16>,
    fork_id: ENRForkID,
    attnets: Bitvector<ATTESTATION_SUBNET_COUNT>,
) -> Result<Enr, NetworkError> {
    let mut builder = discv5::enr::Enr::builder();

    if let Some(ip) = ip4 {
        builder.ip4(ip);
    }
    if let Some(udp) = udp4 {
        builder.udp4(udp);
    }
    if let Some(tcp) = tcp4 {
        builder.tcp4(tcp);
    }

    // SSZ-encode the ENRForkID (16 bytes) and store as RLP byte string.
    let eth2_bytes = fork_id.as_ssz_bytes();
    builder.add_value("eth2", &eth2_bytes.as_slice());

    // SSZ-encode the attnets Bitvector<64> (8 bytes) and store as RLP byte string.
    let attnets_bytes = attnets.as_ssz_bytes();
    builder.add_value("attnets", &attnets_bytes.as_slice());

    // QUIC ports stored as u16 (same RLP encoding as standard udp/tcp fields).
    if let Some(port) = quic_port {
        builder.add_value("quic", &port);
    }
    if let Some(port) = quic6_port {
        builder.add_value("quic6", &port);
    }

    builder
        .build(secret_key)
        .map_err(|e| NetworkError::Discv5(e.to_string()))
}

// ── Field readers ─────────────────────────────────────────────────────────────

/// Decode the `eth2` ENR key into an `ENRForkID`.
///
/// Returns `Err(NetworkError::Discv5)` if the key is absent.
/// Returns `Err(NetworkError::Ssz)` if the SSZ bytes are malformed.
pub fn read_eth2_field(enr: &Enr) -> Result<ENRForkID, NetworkError> {
    let rlp = enr
        .get_raw_rlp("eth2")
        .ok_or_else(|| NetworkError::Discv5("missing eth2 ENR key".into()))?;
    let raw = rlp_decode_bytes(rlp)
        .ok_or_else(|| NetworkError::Discv5("malformed RLP in eth2 ENR key".into()))?;
    ENRForkID::from_ssz_bytes(raw).map_err(NetworkError::Ssz)
}

/// Decode the `attnets` ENR key into a `Bitvector<ATTESTATION_SUBNET_COUNT>`.
///
/// Returns `Err(NetworkError::Discv5)` if the key is absent.
/// Returns `Err(NetworkError::Ssz)` if the SSZ bytes are malformed.
pub fn read_attnets_field(enr: &Enr) -> Result<Bitvector<ATTESTATION_SUBNET_COUNT>, NetworkError> {
    let rlp = enr
        .get_raw_rlp("attnets")
        .ok_or_else(|| NetworkError::Discv5("missing attnets ENR key".into()))?;
    let raw = rlp_decode_bytes(rlp)
        .ok_or_else(|| NetworkError::Discv5("malformed RLP in attnets ENR key".into()))?;
    Bitvector::<ATTESTATION_SUBNET_COUNT>::from_ssz_bytes(raw).map_err(NetworkError::Ssz)
}

/// Decode the `quic` ENR key as a `u16` IPv4 QUIC UDP port.
///
/// Returns `None` if the key is absent or malformed (QUIC is optional on
/// remote peers; absence is not an error).
pub fn read_quic_port(enr: &Enr) -> Option<u16> {
    enr.get_decodable::<u16>("quic")?.ok()
}

/// Decode the `quic6` ENR key as a `u16` IPv6 QUIC UDP port.
///
/// Returns `None` if the key is absent or malformed.
pub fn read_quic6_port(enr: &Enr) -> Option<u16> {
    enr.get_decodable::<u16>("quic6")?.ok()
}

// ── matches_local_fork ────────────────────────────────────────────────────────

/// Return `true` if the peer's fork digest matches the local fork digest.
///
/// Per `specs/phase0/p2p-interface.md:1708-1715`: nodes MUST reject peers
/// whose `fork_digest` differs. Differences in `next_fork_version` or
/// `next_fork_epoch` are permitted (MAY accept, per the spec's MAY clause).
pub fn matches_local_fork(local: &ENRForkID, peer: &ENRForkID) -> bool {
    local.fork_digest == peer.fork_digest
}

// ── ENR → dial multiaddr ──────────────────────────────────────────────────────

/// Convert a discv5 ENR into a libp2p dial multiaddr.
///
/// Returns `/ip4/<ip4>/tcp/<tcp4>/p2p/<peer_id>` when the ENR carries ip4 and
/// tcp4 fields; falls back to `/ip6/<ip6>/tcp/<tcp6>/p2p/<peer_id>` otherwise.
/// Returns `None` when neither ip4+tcp4 nor ip6+tcp6 are present, or when the
/// ENR's public key cannot be decoded as a secp256k1 key.
pub fn enr_to_dial_multiaddr(enr: &Enr) -> Option<Multiaddr> {
    // Derive the libp2p PeerId from the ENR's secp256k1 public key.
    let peer_id = {
        let combined_pk = enr.public_key();
        // Only secp256k1 ENRs are valid on the Ethereum CL p2p network.
        let compressed = match &combined_pk {
            CombinedPublicKey::Secp256k1(_) => combined_pk.encode(), // 33 bytes compressed
            CombinedPublicKey::Ed25519(_) => return None,
        };
        let secp_pk = libp2p::identity::secp256k1::PublicKey::try_from_bytes(&compressed).ok()?;
        let identity_pk = libp2p::identity::PublicKey::from(secp_pk);
        libp2p::PeerId::from_public_key(&identity_pk)
    };

    // Prefer IPv4 + TCP4.
    if let (Some(ip4), Some(tcp4)) = (enr.ip4(), enr.tcp4()) {
        let base: Multiaddr = format!("/ip4/{ip4}/tcp/{tcp4}").parse().ok()?;
        return base.with_p2p(peer_id).ok();
    }

    // Fall back to IPv6 + TCP6.
    if let (Some(ip6), Some(tcp6)) = (enr.ip6(), enr.tcp6()) {
        let base: Multiaddr = format!("/ip6/{ip6}/tcp/{tcp6}").parse().ok()?;
        return base.with_p2p(peer_id).ok();
    }

    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_utils::{Bytes4, Epoch};

    fn test_fork_id() -> ENRForkID {
        ENRForkID {
            fork_digest: Bytes4::from_array([0x01, 0x02, 0x03, 0x04]),
            next_fork_version: Bytes4::from_array([0xde, 0xad, 0xbe, 0xef]),
            next_fork_epoch: Epoch(100),
        }
    }

    fn test_attnets() -> Bitvector<ATTESTATION_SUBNET_COUNT> {
        let mut bv = Bitvector::<ATTESTATION_SUBNET_COUNT>::new();
        bv.set(0, true);
        bv.set(5, true);
        bv.set(63, true);
        bv
    }

    // ── Task 1.3: ENR round-trip ───────────────────────────────────────────────

    /// Round-trip ENR with all four port keys (udp4=9000, tcp4=9000, quic=9001,
    /// quic6=9001). Decode each field and assert equality with the input.
    #[test]
    fn enr_roundtrip_all_ports() {
        let key = CombinedKey::generate_secp256k1();
        let fork_id = test_fork_id();
        let attnets = test_attnets();

        let enr = build_local_enr(
            &key,
            Some(Ipv4Addr::new(127, 0, 0, 1)),
            Some(9000),
            Some(9000),
            Some(9001),
            Some(9001),
            fork_id.clone(),
            attnets.clone(),
        )
        .expect("build_local_enr failed");

        // Standard fields
        assert_eq!(enr.ip4(), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(enr.udp4(), Some(9000));
        assert_eq!(enr.tcp4(), Some(9000));

        // Custom QUIC fields
        assert_eq!(read_quic_port(&enr), Some(9001));
        assert_eq!(read_quic6_port(&enr), Some(9001));

        // eth2 field round-trip
        let decoded_fork_id = read_eth2_field(&enr).expect("read_eth2_field failed");
        assert_eq!(decoded_fork_id, fork_id);

        // attnets field round-trip
        let decoded_attnets = read_attnets_field(&enr).expect("read_attnets_field failed");
        assert_eq!(decoded_attnets.as_ssz_bytes(), attnets.as_ssz_bytes());
    }

    /// Verify the quic key round-trip on a synthesised ENR (no bootnode ENR
    /// available with a quic key in the local spec checkout).
    ///
    /// A real Lighthouse mainnet bootnode ENR such as:
    ///   enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspz...
    /// would carry `quic` only if the bootnode runs QUIC. We synthesise an ENR
    /// with quic=9001 and verify the round-trip, which exercises the same code
    /// path as a real Lighthouse ENR would.
    #[test]
    fn quic_key_roundtrip_synthesised() {
        let key = CombinedKey::generate_secp256k1();
        let fork_id = test_fork_id();
        let attnets = Bitvector::<ATTESTATION_SUBNET_COUNT>::new();

        let enr = build_local_enr(&key, None, None, None, Some(9001), None, fork_id, attnets)
            .expect("build_local_enr failed");

        assert_eq!(read_quic_port(&enr), Some(9001));
        assert_eq!(read_quic6_port(&enr), None);
    }

    // ── Task 1.4: missing-field paths ─────────────────────────────────────────

    /// Decoding `eth2` from an ENR that has no `eth2` key returns an error.
    #[test]
    fn read_eth2_missing_returns_error() {
        let key = CombinedKey::generate_secp256k1();
        let enr = discv5::enr::Enr::builder()
            .build(&key)
            .expect("empty ENR build failed");

        let err = read_eth2_field(&enr).unwrap_err();
        assert!(
            matches!(err, NetworkError::Discv5(_)),
            "expected Discv5 error, got {err:?}"
        );
    }

    /// Decoding `attnets` from an ENR that has no `attnets` key returns an error.
    #[test]
    fn read_attnets_missing_returns_error() {
        let key = CombinedKey::generate_secp256k1();
        let enr = discv5::enr::Enr::builder()
            .build(&key)
            .expect("empty ENR build failed");

        let err = read_attnets_field(&enr).unwrap_err();
        assert!(
            matches!(err, NetworkError::Discv5(_)),
            "expected Discv5 error, got {err:?}"
        );
    }

    /// `read_quic_port` returns `None` for an ENR without the `quic` key.
    #[test]
    fn read_quic_missing_returns_none() {
        let key = CombinedKey::generate_secp256k1();
        let enr = discv5::enr::Enr::builder()
            .build(&key)
            .expect("empty ENR build failed");

        assert_eq!(read_quic_port(&enr), None);
    }

    // ── enr_to_dial_multiaddr ─────────────────────────────────────────────────

    #[test]
    fn enr_to_dial_multiaddr_ip4() {
        let key = CombinedKey::generate_secp256k1();
        let fork_id = test_fork_id();
        let attnets = test_attnets();

        let enr = build_local_enr(
            &key,
            Some(Ipv4Addr::new(127, 0, 0, 1)),
            Some(9000),
            Some(9000),
            None,
            None,
            fork_id,
            attnets,
        )
        .expect("build_local_enr failed");

        let addr = enr_to_dial_multiaddr(&enr).expect("enr_to_dial_multiaddr returned None");
        let s = addr.to_string();
        assert!(
            s.contains("/ip4/127.0.0.1/tcp/9000/p2p/"),
            "unexpected multiaddr: {s}"
        );
    }

    #[test]
    fn enr_to_dial_multiaddr_no_tcp_returns_none() {
        // An ENR without any ip/tcp fields should yield None.
        let key = CombinedKey::generate_secp256k1();
        let enr = discv5::enr::Enr::builder()
            .build(&key)
            .expect("empty ENR build failed");
        assert!(enr_to_dial_multiaddr(&enr).is_none());
    }

    /// `read_quic6_port` returns `None` for an ENR without the `quic6` key.
    #[test]
    fn read_quic6_missing_returns_none() {
        let key = CombinedKey::generate_secp256k1();
        let enr = discv5::enr::Enr::builder()
            .build(&key)
            .expect("empty ENR build failed");

        assert_eq!(read_quic6_port(&enr), None);
    }

    // ── Task 1.5: matches_local_fork ──────────────────────────────────────────

    #[test]
    fn matches_local_fork_same_digest() {
        let a = ENRForkID {
            fork_digest: Bytes4::from_array([0xAB, 0xCD, 0xEF, 0x01]),
            next_fork_version: Bytes4::from_array([0x00, 0x00, 0x00, 0x01]),
            next_fork_epoch: Epoch(0),
        };
        let b = ENRForkID {
            fork_digest: Bytes4::from_array([0xAB, 0xCD, 0xEF, 0x01]),
            next_fork_version: Bytes4::from_array([0x00, 0x00, 0x00, 0x02]),
            next_fork_epoch: Epoch(999),
        };
        assert!(matches_local_fork(&a, &b));
    }

    #[test]
    fn matches_local_fork_different_digest() {
        let a = ENRForkID {
            fork_digest: Bytes4::from_array([0x01, 0x02, 0x03, 0x04]),
            next_fork_version: Bytes4::from_array([0x00; 4]),
            next_fork_epoch: Epoch(0),
        };
        let b = ENRForkID {
            fork_digest: Bytes4::from_array([0x05, 0x06, 0x07, 0x08]),
            next_fork_version: Bytes4::from_array([0x00; 4]),
            next_fork_epoch: Epoch(0),
        };
        assert!(!matches_local_fork(&a, &b));
    }
}
