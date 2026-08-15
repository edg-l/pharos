//! Gossipsub message-id computation per `specs/phase0/p2p-interface.md:486-498`
//! and `specs/altair/p2p-interface.md:163-171`.
//!
//! ## Phase-0 formula (fork-digest matches phase-0 digest)
//!
//! - Valid snappy: `SHA256(DOMAIN_VALID   || decompressed_data)[:20]`
//! - Invalid snappy: `SHA256(DOMAIN_INVALID || raw_data)[:20]`
//!
//! ## Altair formula (fork-digest does not match phase-0 digest)
//!
//! - Valid snappy:
//!   `SHA256(DOMAIN_VALID || uint_to_bytes(uint64(len(topic))) || topic || decompressed_data)[:20]`
//! - Invalid snappy:
//!   `SHA256(DOMAIN_INVALID || uint_to_bytes(uint64(len(topic))) || topic || raw_data)[:20]`
//!
//! `uint_to_bytes(uint64(n))` is 8 little-endian bytes per the spec helpers.
//!
//! Domain bytes per `p2p-interface.md:232-233`.
//!
//! Snappy format: gossip uses block (raw) compression per
//! `p2p-interface.md:1038-1048`. The message-id decompression therefore tries
//! block decompression.
//!
//! ## Fork dispatch
//!
//! The fork digest is extracted from the topic string
//! (`/eth2/<fork_digest_hex>/<name>/ssz_snappy`) without taking a `ForkContext`
//! argument. The closure in `config.rs` captures the phase-0 fork-digest once
//! at construction time; any topic whose fork-digest hex differs from phase-0
//! uses the altair formula.

use sha2::{Digest, Sha256};

use crate::codec::{MAX_PAYLOAD_SIZE, snappy_block::decode_snappy_block};

/// Domain tag for messages that successfully decode as snappy block compression.
///
/// Per `p2p-interface.md:232`.
pub const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Domain tag for messages that fail snappy decoding.
///
/// Per `p2p-interface.md:233`.
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Extract the 4-byte fork digest from a topic string.
///
/// Topic format: `/eth2/<8-hex-chars>/<name>/ssz_snappy`
/// Returns `None` if the string cannot be parsed.
pub fn parse_fork_digest_from_topic_str(topic_str: &str) -> Option<[u8; 4]> {
    // Split produces ["", "eth2", "<hex>", "<name>", "ssz_snappy"].
    let parts: Vec<&str> = topic_str.split('/').collect();
    if parts.len() != 5 {
        return None;
    }
    let hex_str = parts[2];
    if hex_str.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let hi = hex_nibble(hex_str.as_bytes()[i * 2])?;
        let lo = hex_nibble(hex_str.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(bytes)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Compute the 20-byte gossipsub message-id for `raw_data` on topic `topic_str`.
///
/// Dispatches to the phase-0 or altair formula based on whether the topic's
/// fork-digest matches `phase0_fork_digest`:
///
/// - **Phase-0 digest**: no topic bytes in preimage
///   (`specs/phase0/p2p-interface.md:486-498`).
/// - **Any other digest** (altair and later): topic length + topic in preimage
///   (`specs/altair/p2p-interface.md:163-171`).
///
/// `phase0_fork_digest` MUST be captured once from `ForkContext` when the
/// gossipsub behaviour is built (in `gossip/config.rs`) and passed here on
/// every message.
pub fn compute_message_id(
    topic_str: &str,
    raw_data: &[u8],
    phase0_fork_digest: &[u8; 4],
) -> [u8; 20] {
    let topic_digest = parse_fork_digest_from_topic_str(topic_str);
    let is_phase0 = topic_digest.as_ref() == Some(phase0_fork_digest);

    // Try snappy-block decompress.
    let decompressed = decode_snappy_block(raw_data, MAX_PAYLOAD_SIZE).ok();

    if is_phase0 {
        // Phase-0 formula: no topic in preimage.
        let (domain, payload): ([u8; 4], &[u8]) = match &decompressed {
            Some(d) => (MESSAGE_DOMAIN_VALID_SNAPPY, d.as_slice()),
            None => (MESSAGE_DOMAIN_INVALID_SNAPPY, raw_data),
        };
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(payload);
        let full = hasher.finalize();
        let mut id = [0u8; 20];
        id.copy_from_slice(&full[..20]);
        id
    } else {
        // Altair formula: topic length (8 LE bytes) + topic bytes in preimage.
        let topic_bytes = topic_str.as_bytes();
        let topic_len_le = (topic_bytes.len() as u64).to_le_bytes();
        let (domain, payload): ([u8; 4], &[u8]) = match &decompressed {
            Some(d) => (MESSAGE_DOMAIN_VALID_SNAPPY, d.as_slice()),
            None => (MESSAGE_DOMAIN_INVALID_SNAPPY, raw_data),
        };
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(topic_len_le);
        hasher.update(topic_bytes);
        hasher.update(payload);
        let full = hasher.finalize();
        let mut id = [0u8; 20];
        id.copy_from_slice(&full[..20]);
        id
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::snappy_block::encode_snappy_block;
    use pharos_utils::hash::hash_concat;
    use sha2::{Digest, Sha256};

    // Phase-0 fork digest used in all phase-0 tests.
    const PHASE0_FD: [u8; 4] = [0xab, 0xcd, 0xef, 0x01];
    // Altair fork digest (any value different from PHASE0_FD).
    const ALTAIR_FD: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

    fn phase0_topic() -> String {
        format!(
            "/eth2/{:08x}/beacon_block/ssz_snappy",
            u32::from_be_bytes(PHASE0_FD)
        )
    }

    fn altair_topic() -> String {
        format!(
            "/eth2/{:08x}/sync_committee_contribution_and_proof/ssz_snappy",
            u32::from_be_bytes(ALTAIR_FD)
        )
    }

    /// Valid-snappy and invalid-snappy paths produce different ids for the same
    /// payload on a phase-0 topic.
    #[test]
    fn valid_vs_invalid_differ() {
        let payload = b"hello, ethereum";
        let encoded = encode_snappy_block(payload).expect("encode failed");

        let id_valid = compute_message_id(&phase0_topic(), &encoded, &PHASE0_FD);
        let id_invalid = compute_message_id(&phase0_topic(), payload, &PHASE0_FD);
        assert_ne!(
            id_valid, id_invalid,
            "valid-snappy and invalid-snappy ids must differ"
        );
    }

    /// The id is exactly 20 bytes.
    #[test]
    fn id_is_20_bytes() {
        let payload = b"test";
        let id = compute_message_id(&phase0_topic(), payload, &PHASE0_FD);
        assert_eq!(id.len(), 20);
    }

    /// Same input always yields the same id (deterministic).
    #[test]
    fn id_is_deterministic() {
        let payload = b"determinism test";
        let a = compute_message_id(&phase0_topic(), payload, &PHASE0_FD);
        let b = compute_message_id(&phase0_topic(), payload, &PHASE0_FD);
        assert_eq!(a, b);
    }

    /// Valid-snappy path: encode a known payload, compute id, verify it uses
    /// the valid domain with the PHASE-0 formula (no topic in preimage).
    #[test]
    fn valid_snappy_path_uses_valid_domain() {
        let payload = b"beacon block data";
        let encoded = encode_snappy_block(payload).expect("encode failed");
        let id = compute_message_id(&phase0_topic(), &encoded, &PHASE0_FD);
        // Phase-0 formula: SHA256(DOMAIN_VALID || decompressed)[:20]
        let expected_hash = hash_concat(&MESSAGE_DOMAIN_VALID_SNAPPY, payload);
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&expected_hash.as_slice()[..20]);
        assert_eq!(id, expected);
    }

    /// Invalid-snappy path: raw non-snappy bytes use the invalid domain with
    /// the PHASE-0 formula.
    #[test]
    fn invalid_snappy_path_uses_invalid_domain() {
        let raw = b"not snappy encoded at all";
        let id = compute_message_id(&phase0_topic(), raw, &PHASE0_FD);
        let expected_hash = hash_concat(&MESSAGE_DOMAIN_INVALID_SNAPPY, raw);
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&expected_hash.as_slice()[..20]);
        assert_eq!(id, expected);
    }

    // ── Altair formula tests ───────────────────────────────────────────────────

    /// Altair valid-snappy path: topic is included in the preimage.
    ///
    /// Formula: `SHA256(DOMAIN_VALID || uint_to_bytes(uint64(len(topic))) || topic || decompressed)[:20]`
    #[test]
    fn altair_path_includes_topic_in_preimage_valid() {
        let payload = b"sync committee data";
        let encoded = encode_snappy_block(payload).expect("encode failed");
        let topic = altair_topic();
        let id = compute_message_id(&topic, &encoded, &PHASE0_FD);

        // Hand-compute the expected id.
        let topic_bytes = topic.as_bytes();
        let topic_len_le = (topic_bytes.len() as u64).to_le_bytes();
        let mut hasher = Sha256::new();
        hasher.update(MESSAGE_DOMAIN_VALID_SNAPPY);
        hasher.update(topic_len_le);
        hasher.update(topic_bytes);
        hasher.update(payload); // decompressed
        let full = hasher.finalize();
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&full[..20]);

        assert_eq!(
            id, expected,
            "altair valid-snappy id must match hand-computed value"
        );
    }

    /// Altair invalid-snappy path: topic is included in the preimage with raw data.
    ///
    /// Formula: `SHA256(DOMAIN_INVALID || uint_to_bytes(uint64(len(topic))) || topic || raw_data)[:20]`
    #[test]
    fn altair_path_includes_topic_in_preimage_invalid() {
        let raw = b"not valid snappy data at all for altair test";
        let topic = altair_topic();
        let id = compute_message_id(&topic, raw, &PHASE0_FD);

        // Hand-compute the expected id.
        let topic_bytes = topic.as_bytes();
        let topic_len_le = (topic_bytes.len() as u64).to_le_bytes();
        let mut hasher = Sha256::new();
        hasher.update(MESSAGE_DOMAIN_INVALID_SNAPPY);
        hasher.update(topic_len_le);
        hasher.update(topic_bytes);
        hasher.update(raw);
        let full = hasher.finalize();
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&full[..20]);

        assert_eq!(
            id, expected,
            "altair invalid-snappy id must match hand-computed value"
        );
    }
}
