//! Gossipsub message-id computation per `specs/phase0/p2p-interface.md:486-498`.
//!
//! The message-id is a 20-byte prefix of:
//! - `SHA256(MESSAGE_DOMAIN_VALID_SNAPPY   || decompressed_data)` if snappy decode succeeds.
//! - `SHA256(MESSAGE_DOMAIN_INVALID_SNAPPY || raw_data)` if snappy decode fails.
//!
//! Domain bytes per `p2p-interface.md:232-233`.

use pharos_utils::hash::hash_concat;

use crate::codec::{MAX_PAYLOAD_SIZE, snappy_frame::decode_snappy_frame};

/// Domain tag for messages that successfully decode as snappy framing.
///
/// Per `p2p-interface.md:232`.
pub const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Domain tag for messages that fail snappy decoding.
///
/// Per `p2p-interface.md:233`.
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Compute the 20-byte gossipsub message-id for `raw_data`.
///
/// Algorithm per `specs/phase0/p2p-interface.md:486-498`:
/// 1. Attempt snappy-frame decode with the standard `MAX_PAYLOAD_SIZE` cap.
/// 2. On success: `hash = SHA256(DOMAIN_VALID || decompressed)`.
/// 3. On failure: `hash = SHA256(DOMAIN_INVALID || raw_data)`.
/// 4. Return `hash[..20]`.
pub fn compute_message_id(raw_data: &[u8]) -> [u8; 20] {
    let (domain, payload): ([u8; 4], &[u8]);
    // We need to store the decompressed data so its lifetime covers the hash call.
    let decompressed_storage;
    match decode_snappy_frame(raw_data, MAX_PAYLOAD_SIZE) {
        Ok(decompressed) => {
            decompressed_storage = decompressed;
            domain = MESSAGE_DOMAIN_VALID_SNAPPY;
            payload = &decompressed_storage;
        }
        Err(_) => {
            domain = MESSAGE_DOMAIN_INVALID_SNAPPY;
            payload = raw_data;
            // Zero-init the storage to satisfy the compiler; it is never read.
            decompressed_storage = Vec::new();
            let _ = &decompressed_storage;
        }
    }
    let full = hash_concat(&domain, payload);
    let mut id = [0u8; 20];
    id.copy_from_slice(&full.as_slice()[..20]);
    id
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::snappy_frame::encode_snappy_frame;

    /// Valid-snappy and invalid-snappy paths produce different ids for the same input.
    #[test]
    fn valid_vs_invalid_differ() {
        let payload = b"hello, ethereum";
        let encoded = encode_snappy_frame(payload).expect("encode failed");

        let id_valid = compute_message_id(&encoded);
        let id_invalid = compute_message_id(payload); // not valid snappy framing
        assert_ne!(
            id_valid, id_invalid,
            "valid-snappy and invalid-snappy ids must differ"
        );
    }

    /// The id is exactly 20 bytes.
    #[test]
    fn id_is_20_bytes() {
        let payload = b"test";
        let id = compute_message_id(payload);
        assert_eq!(id.len(), 20);
    }

    /// Same input always yields the same id (deterministic).
    #[test]
    fn id_is_deterministic() {
        let payload = b"determinism test";
        let a = compute_message_id(payload);
        let b = compute_message_id(payload);
        assert_eq!(a, b);
    }

    /// Valid-snappy path: encode a known payload, compute id, verify it uses
    /// the valid domain (id differs from invalid-domain hash of the same raw).
    #[test]
    fn valid_snappy_path_uses_valid_domain() {
        let payload = b"beacon block data";
        let encoded = encode_snappy_frame(payload).expect("encode failed");
        let id = compute_message_id(&encoded);
        // Manually compute expected: SHA256(DOMAIN_VALID || payload)[..20]
        let expected_hash = hash_concat(&MESSAGE_DOMAIN_VALID_SNAPPY, payload);
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&expected_hash.as_slice()[..20]);
        assert_eq!(id, expected);
    }

    /// Invalid-snappy path: raw non-snappy bytes use the invalid domain.
    #[test]
    fn invalid_snappy_path_uses_invalid_domain() {
        let raw = b"not snappy encoded at all";
        let id = compute_message_id(raw);
        let expected_hash = hash_concat(&MESSAGE_DOMAIN_INVALID_SNAPPY, raw);
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&expected_hash.as_slice()[..20]);
        assert_eq!(id, expected);
    }
}
