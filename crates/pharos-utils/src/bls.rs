//! BLS12-381 signature wrappers over `blst`.
//!
//! All verification paths use `blst::min_pk` (pubkeys in G1, signatures in G2)
//! with subgroup checks enabled. Subgroup checks add a small cost but are
//! required for security; performance optimisation is M1+.
//!
//! Public API accepts compressed-byte representations:
//! - `BLSPubkey`   = 48 compressed G1 bytes
//! - `BLSSignature` = 96 compressed G2 bytes
//!
//! Internal `blst` types are only materialised within each function call; the
//! public interface never exposes `blst` types directly so downstream crates
//! need not depend on `blst`.

use blst::{BLST_ERROR, min_pk};
use thiserror::Error;

use crate::bytes::{BLSPubkey, BLSSignature};

/// Domain separation tag used for all signing and verification in Pharos
/// (Ethereum proof-of-stake BLS signing, EIP-2333 POP variant).
///
/// Must match the DST used when signing. Consensus clients sign with
/// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` per the Ethereum spec.
pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Errors returned by BLS operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BlsError {
    /// The supplied 48-byte buffer is not a valid compressed G1 point.
    #[error("invalid BLS public key encoding")]
    InvalidPubkey,

    /// The supplied 96-byte buffer is not a valid compressed G2 point.
    #[error("invalid BLS signature encoding")]
    InvalidSignature,

    /// A byte slice had an unexpected length (neither pubkey nor signature).
    #[error("invalid BLS encoding: unexpected byte length")]
    InvalidEncoding,

    /// Signature verification returned false.
    #[error("BLS signature verification failed")]
    VerificationFailed,

    /// `aggregate` was called with an empty signature slice.
    #[error("cannot aggregate an empty set of signatures")]
    NoSignatures,

    /// `fast_aggregate_verify` was called with an empty public key slice.
    #[error("fast_aggregate_verify requires at least one public key")]
    NoPubkeys,

    /// The supplied 32-byte buffer is not a valid BLS secret key scalar.
    #[error("invalid BLS secret key encoding")]
    InvalidSecretKey,

    /// Raw `blst` error not covered by a more specific variant.
    #[error("blst error: {0}")]
    BlstError(String),
}

impl From<BLST_ERROR> for BlsError {
    fn from(err: BLST_ERROR) -> Self {
        BlsError::BlstError(format!("{err:?}"))
    }
}

/// Decompress a `BLSPubkey` into a `blst` `PublicKey`.
///
/// This only performs curve-membership decoding (via `blst_p1_uncompress`).
/// It does **not** perform the subgroup (G1) check. Callers that pair the
/// pubkey through `sig.verify(..., pk_validate=true)` get the subgroup check
/// inside the pairing loop; callers that use APIs without that flag (e.g.
/// `fast_aggregate_verify`) must use [`parse_pubkey_validated`].
fn parse_pubkey(pk: &BLSPubkey) -> Result<min_pk::PublicKey, BlsError> {
    min_pk::PublicKey::from_bytes(&pk.0).map_err(|_| BlsError::InvalidPubkey)
}

/// Decompress and subgroup-check a `BLSPubkey` into a `blst` `PublicKey`.
///
/// Equivalent to `PublicKey::key_validate`: performs both `blst_p1_uncompress`
/// and `blst_p1_affine_in_g1`. Required for verification paths that do not
/// otherwise subgroup-check the pubkey (e.g. `fast_aggregate_verify`).
fn parse_pubkey_validated(pk: &BLSPubkey) -> Result<min_pk::PublicKey, BlsError> {
    min_pk::PublicKey::key_validate(&pk.0).map_err(|_| BlsError::InvalidPubkey)
}

/// Decompress and validate a `BLSSignature` into a `blst` `Signature`.
///
/// Returns `BlsError::InvalidSignature` on any decoding or subgroup failure.
fn parse_signature(sig: &BLSSignature) -> Result<min_pk::Signature, BlsError> {
    min_pk::Signature::from_bytes(&sig.0).map_err(|_| BlsError::InvalidSignature)
}

/// Verify a single BLS signature.
///
/// Returns `Ok(true)` if the signature is valid for `(pubkey, msg)` using
/// [`BLS_DST`]. Returns `Ok(false)` if the cryptographic verification fails
/// (signature bytes are valid but don't verify). Returns `Err` on decoding
/// errors.
pub fn verify(pubkey: &BLSPubkey, msg: &[u8], signature: &BLSSignature) -> Result<bool, BlsError> {
    let pk = parse_pubkey(pubkey)?;
    let sig = parse_signature(signature)?;
    let result = sig.verify(true, msg, BLS_DST, &[], &pk, true);
    Ok(result == BLST_ERROR::BLST_SUCCESS)
}

/// Aggregate multiple public keys into one by summing G1 points.
///
/// Returns `BlsError::NoPubkeys` when `pubkeys` is empty.
/// Returns `BlsError::InvalidPubkey` if any pubkey fails to validate.
///
/// Used by the `eth_aggregate_pubkeys` BLS conformance test.
pub fn aggregate_pubkeys(pubkeys: &[BLSPubkey]) -> Result<BLSPubkey, BlsError> {
    if pubkeys.is_empty() {
        return Err(BlsError::NoPubkeys);
    }
    let parsed: Result<Vec<min_pk::PublicKey>, BlsError> =
        pubkeys.iter().map(parse_pubkey_validated).collect();
    let parsed = parsed?;
    let refs: Vec<&min_pk::PublicKey> = parsed.iter().collect();
    let agg = min_pk::AggregatePublicKey::aggregate(&refs, true)
        .map_err(|e| BlsError::BlstError(format!("{e:?}")))?;
    Ok(BLSPubkey::from_array(agg.to_public_key().compress()))
}

/// Aggregate multiple signatures into one.
///
/// Returns `BlsError::NoSignatures` when `signatures` is empty.
/// Returns `BlsError::InvalidSignature` if any signature fails to decompress.
pub fn aggregate(signatures: &[BLSSignature]) -> Result<BLSSignature, BlsError> {
    if signatures.is_empty() {
        return Err(BlsError::NoSignatures);
    }

    let parsed: Result<Vec<min_pk::Signature>, BlsError> =
        signatures.iter().map(parse_signature).collect();
    let parsed = parsed?;

    let refs: Vec<&min_pk::Signature> = parsed.iter().collect();
    let agg = min_pk::AggregateSignature::aggregate(&refs, true)
        .map_err(|e| BlsError::BlstError(format!("{e:?}")))?;
    let compressed = agg.to_signature().compress();
    Ok(BLSSignature::from_array(compressed))
}

/// Verify that an aggregate signature is valid for a single message signed by
/// all of the provided public keys.
///
/// `pubkeys` must be non-empty. Returns `Ok(true)` on success, `Ok(false)` on
/// cryptographic failure, `Err` on decoding errors.
pub fn fast_aggregate_verify(
    pubkeys: &[BLSPubkey],
    msg: &[u8],
    signature: &BLSSignature,
) -> Result<bool, BlsError> {
    if pubkeys.is_empty() {
        return Err(BlsError::NoPubkeys);
    }

    // Subgroup-check each pubkey: `fast_aggregate_verify` calls into blst with
    // `pks_validate = false`, so blst does not subgroup-check the keys
    // internally. We must do it here to reject small-subgroup pubkeys.
    let parsed_pks: Result<Vec<min_pk::PublicKey>, BlsError> =
        pubkeys.iter().map(parse_pubkey_validated).collect();
    let parsed_pks = parsed_pks?;

    let pk_refs: Vec<&min_pk::PublicKey> = parsed_pks.iter().collect();
    let sig = parse_signature(signature)?;

    let result = sig.fast_aggregate_verify(true, msg, BLS_DST, &pk_refs);
    Ok(result == BLST_ERROR::BLST_SUCCESS)
}

/// A BLS secret key wrapping `blst::min_pk::SecretKey`.
///
/// Public API is compressed bytes only; the inner `blst` type is never exposed.
///
/// # Zeroization
///
/// `blst::min_pk::SecretKey` is `#[repr(transparent)]` over a `blst_scalar`
/// (`[u8; 32]`, no heap indirection) and itself derives `zeroize::Zeroize` with
/// `#[zeroize(drop)]`, so the inner key is zeroed when dropped. Our `Drop` adds
/// a defense-in-depth `write_bytes` over the same 32 bytes before that runs;
/// both operations target the same inline scalar and are compatible. Neither
/// can clear stack copies the optimizer may have made during construction.
pub struct BLSSecretKey(min_pk::SecretKey);

impl Drop for BLSSecretKey {
    fn drop(&mut self) {
        // Defense-in-depth: blst's SecretKey already zeroizes itself on drop
        // (it derives zeroize::Zeroize), but we additionally overwrite the inner
        // bytes here via write_bytes (a compiler intrinsic the optimizer cannot
        // elide) so key material does not outlive this scope.
        //
        // SAFETY: `self.0` is valid, aligned, and we own it (we're in Drop).
        // The struct is 32 bytes (a `blst_scalar`) and we zero exactly that
        // many bytes.  After this write the value is dropped normally; no
        // double-free risk because we are NOT calling drop again.
        let size = std::mem::size_of::<min_pk::SecretKey>();
        unsafe {
            std::ptr::write_bytes(&mut self.0 as *mut min_pk::SecretKey as *mut u8, 0, size);
        }
    }
}

impl BLSSecretKey {
    /// Deserialize a secret key from a 32-byte big-endian scalar.
    ///
    /// Returns `BlsError::InvalidSecretKey` if the bytes are not a valid
    /// scalar (i.e. `>= curve order` or all zeros for the key value check).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
        min_pk::SecretKey::from_bytes(bytes)
            .map(BLSSecretKey)
            .map_err(|_| BlsError::InvalidSecretKey)
    }

    /// Derive a secret key from initial key material (IKM).
    ///
    /// `ikm` must be at least 32 bytes. Used for test key derivation and
    /// EIP-2333-style key generation. Wraps `SecretKey::key_gen(ikm, &[])`.
    pub fn key_gen(ikm: &[u8]) -> Result<Self, BlsError> {
        min_pk::SecretKey::key_gen(ikm, &[])
            .map(BLSSecretKey)
            .map_err(|_| BlsError::InvalidSecretKey)
    }

    /// Return the compressed public key corresponding to this secret key.
    pub fn to_pubkey(&self) -> BLSPubkey {
        BLSPubkey::from_array(self.0.sk_to_pk().compress())
    }

    /// Sign `msg` using `BLS_DST` (the Ethereum PoS signing DST) and return
    /// the compressed signature.
    pub fn sign(&self, msg: &[u8]) -> BLSSignature {
        let sig = self.0.sign(msg, BLS_DST, &[]);
        BLSSignature::from_array(sig.compress())
    }

    /// Serialize the secret key to 32 big-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// A (pubkey, message, signature) triple for batch verification.
pub struct SignatureSet {
    pub pubkey: BLSPubkey,
    pub message: Vec<u8>,
    pub signature: BLSSignature,
}

/// Verify a batch of signature sets.
///
/// Each set is independently verified. Returns `Ok(true)` only when every set
/// passes; returns `Ok(false)` if any set fails cryptographic verification;
/// returns `Err` if any set has a decoding error.
///
/// This function verifies sets one-by-one. A future optimisation using
/// `blst::Signature::verify_multiple_aggregate_signatures` with random
/// scalars can reduce the number of pairings from `2n` to `n+1` for large
/// batches — that is an M1+ performance item.
pub fn verify_signature_sets(sets: &[SignatureSet]) -> Result<bool, BlsError> {
    for set in sets {
        if !verify(&set.pubkey, &set.message, &set.signature)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::SecretKey;

    /// Derive a test secret key from a fixed 32-byte seed.
    fn test_sk(seed: u8) -> SecretKey {
        let ikm = [seed; 32];
        SecretKey::key_gen(&ikm, &[]).expect("valid ikm")
    }

    /// Sign `msg` with `sk` using [`BLS_DST`] and return the compressed sig.
    fn sign_with_sk(sk: &SecretKey, msg: &[u8]) -> BLSSignature {
        let sig = sk.sign(msg, BLS_DST, &[]);
        BLSSignature::from_array(sig.compress())
    }

    /// Extract compressed pubkey bytes from a `SecretKey`.
    fn pk_bytes(sk: &SecretKey) -> BLSPubkey {
        BLSPubkey::from_array(sk.sk_to_pk().compress())
    }

    #[test]
    fn verify_valid_signature_passes() {
        let sk = test_sk(1);
        let pk = pk_bytes(&sk);
        let msg = b"hello pharos";
        let sig = sign_with_sk(&sk, msg);
        assert!(verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn verify_wrong_message_fails() {
        let sk = test_sk(1);
        let pk = pk_bytes(&sk);
        let msg = b"hello pharos";
        let sig = sign_with_sk(&sk, msg);
        // Different message should fail verification.
        assert!(!verify(&pk, b"wrong message", &sig).unwrap());
    }

    #[test]
    fn verify_wrong_pubkey_fails() {
        let sk = test_sk(1);
        let sk2 = test_sk(2);
        let pk2 = pk_bytes(&sk2); // wrong key
        let msg = b"hello pharos";
        let sig = sign_with_sk(&sk, msg);
        assert!(!verify(&pk2, msg, &sig).unwrap());
    }

    #[test]
    fn aggregate_single_is_identity() {
        // Aggregating a single signature should produce a signature that
        // verifies the same as the original.
        let sk = test_sk(3);
        let pk = pk_bytes(&sk);
        let msg = b"aggregate test";
        let sig = sign_with_sk(&sk, msg);
        let agg = aggregate(&[sig]).unwrap();
        // fast_aggregate_verify with a single pubkey.
        assert!(fast_aggregate_verify(&[pk], msg, &agg).unwrap());
    }

    #[test]
    fn aggregate_empty_returns_no_signatures_error() {
        assert_eq!(aggregate(&[]).unwrap_err(), BlsError::NoSignatures);
    }

    #[test]
    fn fast_aggregate_verify_empty_pubkeys_returns_no_pubkeys_error() {
        let sk = test_sk(1);
        let msg = b"empty pubkeys test";
        let sig = sign_with_sk(&sk, msg);
        let agg = aggregate(&[sig]).unwrap();
        assert_eq!(
            fast_aggregate_verify(&[], msg, &agg).unwrap_err(),
            BlsError::NoPubkeys
        );
    }

    #[test]
    fn batch_verify_one_bad_signature_fails() {
        let sk1 = test_sk(4);
        let sk2 = test_sk(5);
        let msg1 = b"msg one";
        let msg2 = b"msg two";
        let sig1 = sign_with_sk(&sk1, msg1);
        // Use sig1 for sk2/msg2 — wrong signature.
        let bad_sig = sig1;

        let sets = vec![
            SignatureSet {
                pubkey: pk_bytes(&sk1),
                message: msg1.to_vec(),
                signature: sign_with_sk(&sk1, msg1),
            },
            SignatureSet {
                pubkey: pk_bytes(&sk2),
                message: msg2.to_vec(),
                signature: bad_sig,
            },
        ];

        assert!(!verify_signature_sets(&sets).unwrap());
    }

    #[test]
    fn batch_verify_all_valid_passes() {
        let sk1 = test_sk(6);
        let sk2 = test_sk(7);
        let msg1 = b"batch msg one";
        let msg2 = b"batch msg two";

        let sets = vec![
            SignatureSet {
                pubkey: pk_bytes(&sk1),
                message: msg1.to_vec(),
                signature: sign_with_sk(&sk1, msg1),
            },
            SignatureSet {
                pubkey: pk_bytes(&sk2),
                message: msg2.to_vec(),
                signature: sign_with_sk(&sk2, msg2),
            },
        ];

        assert!(verify_signature_sets(&sets).unwrap());
    }

    #[test]
    fn decompression_error_on_corrupted_pubkey_bytes() {
        // A 48-byte buffer of all zeros is not a valid G1 point.
        let bad_pk = BLSPubkey::from_array([0u8; 48]);
        let sk = test_sk(8);
        let msg = b"some message";
        let sig = sign_with_sk(&sk, msg);

        let err = verify(&bad_pk, msg, &sig).unwrap_err();
        assert_eq!(err, BlsError::InvalidPubkey);
    }

    #[test]
    fn decompression_error_on_corrupted_signature_bytes() {
        // A 96-byte buffer of all zeros is not a valid G2 point.
        let sk = test_sk(9);
        let pk = pk_bytes(&sk);
        let bad_sig = BLSSignature::from_array([0u8; 96]);

        let err = verify(&pk, b"any message", &bad_sig).unwrap_err();
        assert_eq!(err, BlsError::InvalidSignature);
    }

    #[test]
    fn fast_aggregate_verify_multi_pubkey() {
        // Three signers, one message: aggregate their signatures, then
        // fast_aggregate_verify against the three pubkeys.
        let sk1 = test_sk(10);
        let sk2 = test_sk(11);
        let sk3 = test_sk(12);
        let msg = b"multi-signer aggregate";

        let sig1 = sign_with_sk(&sk1, msg);
        let sig2 = sign_with_sk(&sk2, msg);
        let sig3 = sign_with_sk(&sk3, msg);
        let agg = aggregate(&[sig1, sig2, sig3]).unwrap();

        let pks = [pk_bytes(&sk1), pk_bytes(&sk2), pk_bytes(&sk3)];
        assert!(fast_aggregate_verify(&pks, msg, &agg).unwrap());

        // Removing one signer should fail verification.
        let pks_short = [pk_bytes(&sk1), pk_bytes(&sk2)];
        assert!(!fast_aggregate_verify(&pks_short, msg, &agg).unwrap());
    }

    #[test]
    fn fast_aggregate_verify_rejects_corrupted_pubkey() {
        // Ensures the subgroup-validated parse path surfaces InvalidPubkey
        // rather than silently accepting a bogus key.
        let sk = test_sk(13);
        let msg = b"subgroup check";
        let sig = sign_with_sk(&sk, msg);
        let agg = aggregate(&[sig]).unwrap();

        let bad_pk = BLSPubkey::from_array([0u8; 48]);
        let err = fast_aggregate_verify(&[bad_pk], msg, &agg).unwrap_err();
        assert_eq!(err, BlsError::InvalidPubkey);
    }

    // ── BLSSecretKey tests ────────────────────────────────────────────────────

    #[test]
    fn sign_then_verify_roundtrip() {
        let ikm = [42u8; 32];
        let sk = BLSSecretKey::key_gen(&ikm).expect("valid ikm");
        let pk = sk.to_pubkey();
        let msg = b"sign then verify";
        let sig = sk.sign(msg);
        assert!(verify(&pk, msg, &sig).unwrap(), "signature must verify");
    }

    #[test]
    fn sign_then_fast_aggregate_verify_single() {
        let ikm = [7u8; 32];
        let sk = BLSSecretKey::key_gen(&ikm).expect("valid ikm");
        let pk = sk.to_pubkey();
        let msg = b"aggregate single signer";
        let sig = sk.sign(msg);
        // Aggregating a single signature then fast_aggregate_verify against
        // one pubkey must succeed.
        let agg = aggregate(&[sig]).unwrap();
        assert!(fast_aggregate_verify(&[pk], msg, &agg).unwrap());
    }

    #[test]
    fn secret_key_to_pubkey_deterministic() {
        // The same IKM must produce the same public key bytes across two
        // independent derivations.
        let ikm = [0xABu8; 32];
        let sk1 = BLSSecretKey::key_gen(&ikm).expect("valid ikm (first)");
        let sk2 = BLSSecretKey::key_gen(&ikm).expect("valid ikm (second)");
        assert_eq!(
            sk1.to_pubkey().0,
            sk2.to_pubkey().0,
            "same IKM must yield the same public key bytes"
        );
    }

    #[test]
    fn secret_key_zeroized_on_drop() {
        // Best-effort test: create a key, record its raw bytes, drop it, then
        // confirm we can no longer read them via any live reference (we can't
        // hold one past the drop, so this test just exercises the Drop impl
        // without panicking — a sanitizer run would catch residual key material).
        //
        // NOTE: the Rust compiler makes no guarantee that stack bytes are
        // cleared even after this Drop; the test exercises the code path but
        // cannot prove the stack frame is clean without a memory sanitizer.
        let ikm = [0x11u8; 32];
        let sk = BLSSecretKey::key_gen(&ikm).expect("valid ikm");
        let _pk = sk.to_pubkey(); // capture pubkey before drop
        drop(sk); // exercises the Drop impl; no panic is the assertion
    }
}
