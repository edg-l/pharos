//! Phase 0 beacon operation containers and networking wire types.
//!
//! Beacon operations defined in `specs/phase0/beacon-chain.md:489-532` and
//! `specs/phase0/beacon-chain.md:590-614` (Signed envelopes).
//! Networking wire types defined in `specs/phase0/p2p-interface.md`.

use pharos_ssz::{Bitlist, Bitvector, Decode, Encode, SszError, SszList, SszVector, TreeHash};
use pharos_utils::{BLSPubkey, BLSSignature, Bytes32};

use crate::phase0::misc::{AttestationData, IndexedAttestation};
use crate::phase0::primitives::{Epoch, ForkDigest, Gwei, Root, Slot, ValidatorIndex, Version};

// ── DepositMessage ────────────────────────────────────────────────────────────

/// `DepositMessage` per `specs/phase0/beacon-chain.md:452-456`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct DepositMessage {
    /// `pubkey: BLSPubkey` — `specs/phase0/beacon-chain.md:453`.
    pub pubkey: BLSPubkey,
    /// `withdrawal_credentials: Bytes32` — `specs/phase0/beacon-chain.md:454`.
    pub withdrawal_credentials: Bytes32,
    /// `amount: Gwei` — `specs/phase0/beacon-chain.md:455`.
    pub amount: Gwei,
}

// ── DepositData ───────────────────────────────────────────────────────────────

/// `DepositData` per `specs/phase0/beacon-chain.md:463-468`.
///
/// Note: `signature` is over `DepositMessage` (`specs/phase0/beacon-chain.md:460`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct DepositData {
    /// `pubkey: BLSPubkey` — `specs/phase0/beacon-chain.md:464`.
    pub pubkey: BLSPubkey,
    /// `withdrawal_credentials: Bytes32` — `specs/phase0/beacon-chain.md:465`.
    pub withdrawal_credentials: Bytes32,
    /// `amount: Gwei` — `specs/phase0/beacon-chain.md:466`.
    pub amount: Gwei,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:467`.
    pub signature: BLSSignature,
}

// ── BeaconBlockHeader ─────────────────────────────────────────────────────────

/// `BeaconBlockHeader` per `specs/phase0/beacon-chain.md:473-479`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BeaconBlockHeader {
    /// `slot: Slot` — `specs/phase0/beacon-chain.md:474`.
    pub slot: Slot,
    /// `proposer_index: ValidatorIndex` — `specs/phase0/beacon-chain.md:475`.
    pub proposer_index: ValidatorIndex,
    /// `parent_root: Root` — `specs/phase0/beacon-chain.md:476`.
    pub parent_root: Root,
    /// `state_root: Root` — `specs/phase0/beacon-chain.md:477`.
    pub state_root: Root,
    /// `body_root: Root` — `specs/phase0/beacon-chain.md:478`.
    pub body_root: Root,
}

// ── SigningData ───────────────────────────────────────────────────────────────

/// `SigningData` per `specs/phase0/beacon-chain.md:484-487`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SigningData {
    /// `object_root: Root` — `specs/phase0/beacon-chain.md:485`.
    pub object_root: Root,
    /// `domain: Domain` — `specs/phase0/beacon-chain.md:486`.
    pub domain: crate::phase0::primitives::Domain,
}

// ── SignedBeaconBlockHeader ───────────────────────────────────────────────────

/// `SignedBeaconBlockHeader` per `specs/phase0/beacon-chain.md:611-614`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedBeaconBlockHeader {
    /// `message: BeaconBlockHeader` — `specs/phase0/beacon-chain.md:612`.
    pub message: BeaconBlockHeader,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:613`.
    pub signature: BLSSignature,
}

// ── ProposerSlashing ──────────────────────────────────────────────────────────

/// `ProposerSlashing` per `specs/phase0/beacon-chain.md:494-497`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ProposerSlashing {
    /// `signed_header_1: SignedBeaconBlockHeader` — `specs/phase0/beacon-chain.md:495`.
    pub signed_header_1: SignedBeaconBlockHeader,
    /// `signed_header_2: SignedBeaconBlockHeader` — `specs/phase0/beacon-chain.md:496`.
    pub signed_header_2: SignedBeaconBlockHeader,
}

// ── AttesterSlashing ──────────────────────────────────────────────────────────

/// `AttesterSlashing` per `specs/phase0/beacon-chain.md:502-505`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const).
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct AttesterSlashing<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `attestation_1: IndexedAttestation` — `specs/phase0/beacon-chain.md:503`.
    pub attestation_1: IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
    /// `attestation_2: IndexedAttestation` — `specs/phase0/beacon-chain.md:504`.
    pub attestation_2: IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
}

// ── Attestation ───────────────────────────────────────────────────────────────

/// `Attestation` per `specs/phase0/beacon-chain.md:510-514`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const).
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Attestation<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE]`
    /// — `specs/phase0/beacon-chain.md:511`.
    pub aggregation_bits: Bitlist<MAX_VALIDATORS_PER_COMMITTEE>,
    /// `data: AttestationData` — `specs/phase0/beacon-chain.md:512`.
    pub data: AttestationData,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:513`.
    pub signature: BLSSignature,
}

// ── Deposit ───────────────────────────────────────────────────────────────────

/// `Deposit` per `specs/phase0/beacon-chain.md:521-524`.
///
/// Generic over `DEPOSIT_PROOF_LENGTH` (= `DEPOSIT_CONTRACT_TREE_DEPTH + 1` = 33).
///
/// For both presets: `DEPOSIT_PROOF_LENGTH = 33`
/// (`specs/phase0/beacon-chain.md:194`: `DEPOSIT_CONTRACT_TREE_DEPTH = 32`).
/// This is a derived constant per the plan (B3).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct Deposit<const DEPOSIT_PROOF_LENGTH: u64> {
    /// `proof: Vector[Bytes32, DEPOSIT_CONTRACT_TREE_DEPTH + 1]`
    /// — `specs/phase0/beacon-chain.md:522`.
    /// `DEPOSIT_PROOF_LENGTH = DEPOSIT_CONTRACT_TREE_DEPTH + 1 = 33`.
    pub proof: SszVector<pharos_utils::Bytes32, DEPOSIT_PROOF_LENGTH>,
    /// `data: DepositData` — `specs/phase0/beacon-chain.md:523`.
    pub data: DepositData,
}

impl<const DEPOSIT_PROOF_LENGTH: u64> Default for Deposit<DEPOSIT_PROOF_LENGTH>
where
    pharos_utils::Bytes32: Default + Clone,
{
    fn default() -> Self {
        Self {
            proof: SszVector::default(),
            data: DepositData::default(),
        }
    }
}

// ── Eth1Block ─────────────────────────────────────────────────────────────────

/// `Eth1Block` per `specs/phase0/validator.md:118-126`.
///
/// Represents a snapshot of an Eth1 block as seen by the beacon chain.
/// Preset-independent: all fields are primitive types.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Eth1Block {
    /// `timestamp: uint64` — `specs/phase0/validator.md:122`.
    pub timestamp: u64,
    /// `deposit_root: Root` — `specs/phase0/validator.md:123`.
    pub deposit_root: Root,
    /// `deposit_count: uint64` — `specs/phase0/validator.md:124`.
    pub deposit_count: u64,
}

// ── AggregateAndProof ─────────────────────────────────────────────────────────

/// `AggregateAndProof` per `specs/phase0/validator.md:128-135`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const) because it
/// wraps `Attestation<MAX_VALIDATORS_PER_COMMITTEE>`.
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct AggregateAndProof<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `aggregator_index: ValidatorIndex` — `specs/phase0/validator.md:132`.
    pub aggregator_index: ValidatorIndex,
    /// `aggregate: Attestation` — `specs/phase0/validator.md:133`.
    pub aggregate: Attestation<MAX_VALIDATORS_PER_COMMITTEE>,
    /// `selection_proof: BLSSignature` — `specs/phase0/validator.md:134`.
    pub selection_proof: BLSSignature,
}

// ── SignedAggregateAndProof ───────────────────────────────────────────────────

/// `SignedAggregateAndProof` per `specs/phase0/validator.md:137-142`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const) because it
/// wraps `AggregateAndProof<MAX_VALIDATORS_PER_COMMITTEE>`.
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedAggregateAndProof<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `message: AggregateAndProof` — `specs/phase0/validator.md:140`.
    pub message: AggregateAndProof<MAX_VALIDATORS_PER_COMMITTEE>,
    /// `signature: BLSSignature` — `specs/phase0/validator.md:141`.
    pub signature: BLSSignature,
}

// ── VoluntaryExit ─────────────────────────────────────────────────────────────

/// `VoluntaryExit` per `specs/phase0/beacon-chain.md:529-532`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct VoluntaryExit {
    /// `epoch: Epoch` — `specs/phase0/beacon-chain.md:530`.
    pub epoch: Epoch,
    /// `validator_index: ValidatorIndex` — `specs/phase0/beacon-chain.md:531`.
    pub validator_index: ValidatorIndex,
}

// ── SignedVoluntaryExit ───────────────────────────────────────────────────────

/// `SignedVoluntaryExit` per `specs/phase0/beacon-chain.md:595-598`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedVoluntaryExit {
    /// `message: VoluntaryExit` — `specs/phase0/beacon-chain.md:596`.
    pub message: VoluntaryExit,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:597`.
    pub signature: BLSSignature,
}

// ── Networking wire types ─────────────────────────────────────────────────────
//
// The following types are p2p interface containers, defined in
// `specs/phase0/p2p-interface.md`.

// ── ENRForkID ─────────────────────────────────────────────────────────────────

/// `ENRForkID` per `specs/phase0/p2p-interface.md:1677-1683`.
///
/// Encoded in the `eth2` ENR key as SSZ bytes.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ENRForkID {
    /// `fork_digest: ForkDigest` — `p2p-interface.md:1679`.
    pub fork_digest: ForkDigest,
    /// `next_fork_version: Version` — `p2p-interface.md:1680`.
    pub next_fork_version: Version,
    /// `next_fork_epoch: Epoch` — `p2p-interface.md:1681`.
    pub next_fork_epoch: Epoch,
}

// ── Status ────────────────────────────────────────────────────────────────────

/// `Status` per `specs/phase0/p2p-interface.md:1325-1333`.
///
/// Exchanged on initial connection to verify fork compatibility.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Status {
    /// `fork_digest: ForkDigest` — `p2p-interface.md:1327`.
    pub fork_digest: ForkDigest,
    /// `finalized_root: Root` — `p2p-interface.md:1328`.
    pub finalized_root: Root,
    /// `finalized_epoch: Epoch` — `p2p-interface.md:1329`.
    pub finalized_epoch: Epoch,
    /// `head_root: Root` — `p2p-interface.md:1330`.
    pub head_root: Root,
    /// `head_slot: Slot` — `p2p-interface.md:1331`.
    pub head_slot: Slot,
}

// ── BeaconBlocksByRangeRequest ────────────────────────────────────────────────

/// `BeaconBlocksByRangeRequest` per `specs/phase0/p2p-interface.md:1413-1417`.
///
/// Note: `step` is deprecated and SHOULD be set to 1
/// (`p2p-interface.md:1415`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BeaconBlocksByRangeRequest {
    /// `start_slot: Slot` — `p2p-interface.md:1414`.
    pub start_slot: Slot,
    /// `count: uint64` — `p2p-interface.md:1415`.
    pub count: u64,
    /// `step: uint64` — `p2p-interface.md:1416` (deprecated; always 1).
    pub step: u64,
}

// ── BeaconBlocksByRootRequest ─────────────────────────────────────────────────

/// `BeaconBlocksByRootRequest` per `specs/phase0/p2p-interface.md:1496-1502`.
///
/// SSZ-encoded as the inner list per the single-field rule
/// (`p2p-interface.md:1308-1309`). `MAX_REQUEST_BLOCKS` caps the list length.
///
/// `Encode`/`Decode` are hand-written (NOT derived) precisely because of that
/// single-field rule: a derived container impl would prepend a 4-byte SSZ
/// offset for the lone variable-length field, but the wire format is the *bare*
/// `List[Root, N]` with no wrapper. Deriving caused peers (e.g. lighthouse) to
/// reject the request as `InvalidByteLength` and ban us on the spot.
#[derive(TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BeaconBlocksByRootRequest<const MAX_REQUEST_BLOCKS: u64> {
    /// The list of block roots requested — `p2p-interface.md:1498`.
    pub block_roots: SszList<Root, MAX_REQUEST_BLOCKS>,
}

impl<const MAX_REQUEST_BLOCKS: u64> Encode for BeaconBlocksByRootRequest<MAX_REQUEST_BLOCKS> {
    // Transparent over `block_roots`: the request IS the list (single-field rule).
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        <SszList<Root, MAX_REQUEST_BLOCKS> as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.block_roots.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.block_roots.ssz_append(buf);
    }
}

impl<const MAX_REQUEST_BLOCKS: u64> Decode for BeaconBlocksByRootRequest<MAX_REQUEST_BLOCKS> {
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        <SszList<Root, MAX_REQUEST_BLOCKS> as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        Ok(Self {
            block_roots: SszList::from_ssz_bytes(bytes)?,
        })
    }
}

// ── MetaData ──────────────────────────────────────────────────────────────────

/// `MetaData` per `specs/phase0/p2p-interface.md:382-387`.
///
/// Advertised via the MetaData req-resp method and encoded in the ENR
/// `attnets` key.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct MetaData {
    /// `seq_number: uint64` — `p2p-interface.md:384`.
    pub seq_number: u64,
    /// `attnets: Bitvector[ATTESTATION_SUBNET_COUNT]` — `p2p-interface.md:385`.
    pub attnets: Bitvector<{ super::primitives::ATTESTATION_SUBNET_COUNT }>,
}

// ── ErrorMessage ──────────────────────────────────────────────────────────────

/// `ErrorMessage` per `specs/phase0/p2p-interface.md:1220-1224`.
///
/// A UTF-8 string (up to 256 bytes) carried in RPC error responses.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ErrorMessage {
    /// Raw UTF-8 bytes of the error string — `p2p-interface.md:1222`.
    pub message: SszList<u8, 256>,
}

impl ErrorMessage {
    /// Returns the message bytes as a lossy UTF-8 string.
    pub fn as_utf8_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.message.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_ssz::{Decode, Encode, TreeHash};
    use pharos_utils::{Bytes4, Epoch, Hash256, Slot};

    // ── BeaconBlocksByRootRequest ─────────────────────────────────────────────

    /// The request must serialize as the *bare* `List[Root, N]` (single-field
    /// rule) — exactly `32 * n` bytes with NO 4-byte container offset. A derived
    /// container impl would prepend the offset; lighthouse rejects that as
    /// `InvalidByteLength` and bans the peer. Empty list MUST be 0 bytes, not 4.
    #[test]
    fn blocks_by_root_request_is_bare_list_no_offset() {
        type Req = BeaconBlocksByRootRequest<1024>;

        // Empty request: zero bytes on the wire (NOT a 4-byte offset).
        let empty = Req::default();
        assert_eq!(
            empty.as_ssz_bytes().len(),
            0,
            "empty request must be 0 bytes"
        );

        // Two roots: exactly 64 bytes, byte-identical to the two roots back-to-back.
        let r0 = Hash256::from([0x11u8; 32]);
        let r1 = Hash256::from([0x22u8; 32]);
        let req = Req {
            block_roots: SszList::from_vec(vec![r0, r1]).unwrap(),
        };
        let bytes = req.as_ssz_bytes();
        assert_eq!(bytes.len(), 64, "two roots must be 2*32 bytes, no offset");
        assert_eq!(&bytes[0..32], r0.as_slice());
        assert_eq!(&bytes[32..64], r1.as_slice());
        assert_eq!(req.ssz_bytes_len(), 64);

        // Round-trips back to the same value.
        let decoded = Req::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(req, decoded);
    }

    // ── ENRForkID ─────────────────────────────────────────────────────────────

    #[test]
    fn enr_fork_id_ssz_roundtrip() {
        let original = ENRForkID {
            fork_digest: Bytes4::from_array([0x01, 0x02, 0x03, 0x04]),
            next_fork_version: Bytes4::from_array([0xde, 0xad, 0xbe, 0xef]),
            next_fork_epoch: Epoch(42),
        };
        let encoded = original.as_ssz_bytes();
        // Fixed size: 4 (fork_digest) + 4 (next_fork_version) + 8 (epoch) = 16 bytes.
        assert_eq!(encoded.len(), 16);
        let decoded = ENRForkID::from_ssz_bytes(&encoded).expect("decode ENRForkID");
        assert_eq!(original, decoded);
    }

    #[test]
    fn enr_fork_id_tree_hash_deterministic() {
        let a = ENRForkID {
            fork_digest: Bytes4::from_array([0xaa, 0xbb, 0xcc, 0xdd]),
            next_fork_version: Bytes4::from_array([0x00, 0x00, 0x00, 0x01]),
            next_fork_epoch: Epoch(100),
        };
        let root1 = a.tree_hash_root();
        let root2 = a.tree_hash_root();
        assert_eq!(root1, root2, "tree_hash_root must be deterministic");
        // Mutated copy must differ.
        let b = ENRForkID {
            fork_digest: Bytes4::from_array([0x00, 0x00, 0x00, 0x00]),
            ..a
        };
        assert_ne!(
            root1,
            b.tree_hash_root(),
            "different ENRForkID must hash differently"
        );
    }

    // ── Status ────────────────────────────────────────────────────────────────

    #[test]
    fn status_ssz_roundtrip() {
        let original = Status {
            fork_digest: Bytes4::from_array([0xde, 0xad, 0xbe, 0xef]),
            finalized_root: Hash256::from_array([0x11u8; 32]),
            finalized_epoch: Epoch(99),
            head_root: Hash256::from_array([0x22u8; 32]),
            head_slot: Slot(800),
        };
        let encoded = original.as_ssz_bytes();
        // Fixed size: 4 + 32 + 8 + 32 + 8 = 84 bytes.
        assert_eq!(encoded.len(), 84);
        let decoded = Status::from_ssz_bytes(&encoded).expect("decode Status");
        assert_eq!(original, decoded);
    }

    #[test]
    fn status_tree_hash_deterministic() {
        let s = Status {
            fork_digest: Bytes4::from_array([0x01, 0x00, 0x00, 0x00]),
            finalized_root: Hash256::default(),
            finalized_epoch: Epoch(0),
            head_root: Hash256::default(),
            head_slot: Slot(0),
        };
        assert_eq!(s.tree_hash_root(), s.tree_hash_root());
        let s2 = Status {
            head_slot: Slot(1),
            ..s
        };
        assert_ne!(s.tree_hash_root(), s2.tree_hash_root());
    }

    // ── MetaData ──────────────────────────────────────────────────────────────

    #[test]
    fn metadata_ssz_roundtrip() {
        let mut m = MetaData {
            seq_number: 7,
            ..MetaData::default()
        };
        m.attnets.set(0, true);
        m.attnets.set(63, true);
        let encoded = m.as_ssz_bytes();
        // Fixed size: 8 (seq_number) + 8 (attnets bitvector = 64 bits / 8) = 16 bytes.
        assert_eq!(encoded.len(), 16);
        let decoded = MetaData::from_ssz_bytes(&encoded).expect("decode MetaData");
        assert_eq!(m.seq_number, decoded.seq_number);
        assert_eq!(m.attnets.get(0), decoded.attnets.get(0));
        assert_eq!(m.attnets.get(63), decoded.attnets.get(63));
    }

    #[test]
    fn metadata_tree_hash_deterministic() {
        let m = MetaData::default();
        assert_eq!(m.tree_hash_root(), m.tree_hash_root());
    }
}
