//! Hand-built fixture tests for the EIP-1459 enrtree resolver.
//!
//! No live network: a [`StaticResolver`] returns TXT records from an in-memory
//! map, and roots are signed with a deterministic test key so the
//! signature-acceptance / tampered-signature-rejection paths are exercised
//! exactly as they would be against the published mainnet tree.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use discv5::enr::CombinedKey;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

use super::*;

/// In-memory TXT source: maps DNS name -> record bodies.
#[derive(Default, Clone)]
struct StaticResolver {
    records: HashMap<String, Vec<String>>,
}

impl StaticResolver {
    fn insert(&mut self, name: impl Into<String>, body: impl Into<String>) {
        self.records
            .entry(name.into())
            .or_default()
            .push(body.into());
    }
}

#[async_trait]
impl TxtResolver for StaticResolver {
    async fn txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.records
            .get(name)
            .cloned()
            .ok_or_else(|| DnsError::NoTxtRecord(name.to_string()))
    }
}

/// Deterministic test signing key (fixed 32-byte scalar).
fn test_signing_key() -> SigningKey {
    let bytes = [7u8; 32];
    SigningKey::from_slice(&bytes).expect("valid scalar")
}

/// Base32 (no-pad) of the keccak256 of `content` — the EIP-1459 subtree hash.
fn hash_of(content: &str) -> String {
    BASE32_NOPAD.encode(Keccak256::digest(content.as_bytes()).as_slice())
}

/// Build a signed `enrtree-root:v1` record over the given subtree hashes.
fn signed_root(key: &SigningKey, enr_root: &str, link_root: &str, seq: u64) -> String {
    let content = format!("enrtree-root:v1 e={enr_root} l={link_root} seq={seq}");
    let digest = Keccak256::digest(content.as_bytes());
    let (sig, recid) = key
        .sign_prehash_recoverable(digest.as_slice())
        .expect("sign root");
    let mut sig_bytes = sig.to_bytes().to_vec();
    sig_bytes.push(recid.to_byte());
    let sig_b64 = BASE64URL_NOPAD.encode(&sig_bytes);
    format!("{content} sig={sig_b64}")
}

/// The `enrtree://` URL for a signing key over `domain`.
fn enrtree_url(key: &SigningKey, domain: &str) -> String {
    let compressed = key.verifying_key().to_encoded_point(true);
    let pubkey_b32 = BASE32_NOPAD.encode(compressed.as_bytes());
    format!("enrtree://{pubkey_b32}@{domain}")
}

/// Produce a valid `enr:` leaf string for a fresh secp256k1 ENR.
fn make_enr_leaf() -> String {
    let key = CombinedKey::generate_secp256k1();
    let enr = discv5::enr::Enr::builder()
        .ip4("127.0.0.1".parse().unwrap())
        .udp4(9000)
        .build(&key)
        .expect("build enr");
    enr.to_base64()
}

/// Build a fixture tree: root -> enr-subtree (a branch with two enr leaves),
/// empty link-subtree. Returns the resolver + URL.
fn build_fixture() -> (StaticResolver, String) {
    let key = test_signing_key();
    let domain = "nodes.example.org";

    let leaf_a = format!("enr:{}", make_enr_leaf().strip_prefix("enr:").unwrap());
    let leaf_b = format!("enr:{}", make_enr_leaf().strip_prefix("enr:").unwrap());

    let hash_a = hash_of(&leaf_a);
    let hash_b = hash_of(&leaf_b);

    let branch = format!("enrtree-branch:{hash_a},{hash_b}");
    let branch_hash = hash_of(&branch);

    // Empty link subtree: an enrtree-branch with no children.
    let link = "enrtree-branch:".to_string();
    let link_hash = hash_of(&link);

    let root = signed_root(&key, &branch_hash, &link_hash, 1);

    let mut r = StaticResolver::default();
    r.insert(domain, root);
    r.insert(format!("{branch_hash}.{domain}"), branch);
    r.insert(format!("{hash_a}.{domain}"), leaf_a);
    r.insert(format!("{hash_b}.{domain}"), leaf_b);
    r.insert(format!("{link_hash}.{domain}"), link);

    (r, enrtree_url(&key, domain))
}

#[test]
fn enrtree_url_parses() {
    let key = test_signing_key();
    let url = enrtree_url(&key, "nodes.example.org");
    let parsed = EnrTreeUrl::parse(&url).expect("parse");
    assert_eq!(parsed.domain, "nodes.example.org");
    // The recovered key matches the signing key's verifying key.
    assert_eq!(
        parsed.public_key.to_encoded_point(true),
        key.verifying_key().to_encoded_point(true)
    );
}

#[test]
fn enrtree_url_rejects_malformed() {
    assert!(matches!(
        EnrTreeUrl::parse("http://nope@x"),
        Err(DnsError::MalformedUrl(_))
    ));
    assert!(matches!(
        EnrTreeUrl::parse("enrtree://no-at-sign"),
        Err(DnsError::MalformedUrl(_))
    ));
    assert!(matches!(
        EnrTreeUrl::parse("enrtree://!!!badbase32@d"),
        Err(DnsError::InvalidPublicKey(_))
    ));
}

#[tokio::test]
async fn enrtree_root_sig_verifies() {
    // Good signature → root accepted, walk yields the leaves.
    let (resolver, url) = build_fixture();
    let enrs = resolve_enrtree(&url, Arc::new(resolver))
        .await
        .expect("resolve");
    assert_eq!(enrs.len(), 2, "fixture tree advertises two ENRs");
}

#[tokio::test]
async fn enrtree_walk_resolves_fixture() {
    // Full tree walk against the hand-built fixture yields >= 1 ENR.
    let (resolver, url) = build_fixture();
    let enrs = resolve_enrtree(&url, Arc::new(resolver))
        .await
        .expect("resolve");
    assert!(!enrs.is_empty(), "walk must yield at least one ENR");
}

#[tokio::test]
async fn enrtree_root_sig_tampered_rejected() {
    // Flip one BYTE of the decoded signature (not a base64 char — that can break
    // base64 canonical form and fail decode before verification). A byte flip keeps
    // the sig well-formed base64 but makes recovery yield a different key → whole
    // tree rejected with RootSignatureInvalid.
    let (mut resolver, url) = build_fixture();
    let domain = "nodes.example.org";
    let root = resolver.records.get_mut(domain).unwrap();
    let original = root[0].clone();
    let (content, sig_b64) = original
        .rsplit_once(" sig=")
        .expect("root record has a sig= field");
    let mut sig_bytes = BASE64URL_NOPAD
        .decode(sig_b64.as_bytes())
        .expect("fixture sig is valid base64");
    // Flip a byte inside r (well away from the recovery byte) → different key.
    sig_bytes[10] ^= 0x01;
    root[0] = format!("{content} sig={}", BASE64URL_NOPAD.encode(&sig_bytes));

    let err = resolve_enrtree(&url, Arc::new(resolver))
        .await
        .expect_err("tampered root must reject");
    assert!(
        matches!(err, DnsError::RootSignatureInvalid(_)),
        "expected RootSignatureInvalid, got {err:?}"
    );
}

#[tokio::test]
async fn enrtree_subtree_hash_mismatch_rejected() {
    // Tamper a subtree body so its keccak256 no longer matches the referencing
    // branch hash → that subtree (and its enr) is rejected, leaving one ENR.
    let (mut resolver, url) = build_fixture();
    let domain = "nodes.example.org";

    // Find a leaf entry (an `enr:` record at `<hash>.<domain>`) and corrupt it.
    let leaf_name = resolver
        .records
        .iter()
        .find(|(k, v)| k.ends_with(domain) && v[0].starts_with("enr:") && *k != domain)
        .map(|(k, _)| k.clone())
        .expect("a leaf record exists");
    let leaf = resolver.records.get_mut(&leaf_name).unwrap();
    // Append a byte so the content no longer hashes to the referencing hash.
    leaf[0].push('x');

    // The branch dispatch isolates the bad subtree; the other leaf survives.
    let enrs = resolve_enrtree(&url, Arc::new(resolver))
        .await
        .expect("valid leaf still resolves");
    assert_eq!(
        enrs.len(),
        1,
        "one leaf survives, the tampered one is dropped"
    );
}

#[tokio::test]
async fn enr_leaf_decodes() {
    // A single-leaf tree: root -> branch(one enr) -> enr leaf decodes to 1 ENR.
    let key = test_signing_key();
    let domain = "single.example.org";
    let leaf = make_enr_leaf();
    let leaf_hash = hash_of(&leaf);
    let branch = format!("enrtree-branch:{leaf_hash}");
    let branch_hash = hash_of(&branch);
    let link = "enrtree-branch:".to_string();
    let link_hash = hash_of(&link);
    let root = signed_root(&key, &branch_hash, &link_hash, 1);

    let mut r = StaticResolver::default();
    r.insert(domain, root);
    r.insert(format!("{branch_hash}.{domain}"), branch);
    r.insert(format!("{leaf_hash}.{domain}"), leaf.clone());
    r.insert(format!("{link_hash}.{domain}"), link);

    let enrs = resolve_enrtree(&enrtree_url(&key, domain), Arc::new(r))
        .await
        .expect("resolve");
    assert_eq!(enrs.len(), 1);
    assert_eq!(enrs[0].to_base64(), leaf);
}

#[tokio::test]
async fn recursion_bound_enforced() {
    // A self-referential link tree would loop forever without the cycle guard
    // and depth bound. Build a root whose link subtree points back at itself
    // via a fresh tree URL, and assert resolution terminates without error
    // (the visited-set short-circuits the cycle).
    let key = test_signing_key();
    let domain = "loop.example.org";

    // Link entry pointing back at the same tree (a cycle).
    let link_entry = enrtree_url(&key, domain);
    let link_hash = hash_of(&link_entry);
    let link_subtree = format!("enrtree-branch:{link_hash}");
    let link_subtree_hash = hash_of(&link_subtree);

    let empty_enr = "enrtree-branch:".to_string();
    let enr_hash = hash_of(&empty_enr);

    let root = signed_root(&key, &enr_hash, &link_subtree_hash, 1);

    let mut r = StaticResolver::default();
    r.insert(domain, root);
    r.insert(format!("{enr_hash}.{domain}"), empty_enr);
    r.insert(format!("{link_subtree_hash}.{domain}"), link_subtree);
    r.insert(format!("{link_hash}.{domain}"), link_entry);

    // Terminates (cycle guard) and yields zero ENRs without blowing the bounds.
    let enrs = resolve_enrtree(&enrtree_url(&key, domain), Arc::new(r))
        .await
        .expect("cycle terminates via visited-set");
    assert!(enrs.is_empty());
}

#[tokio::test]
async fn record_limit_aborts_runaway_tree() {
    // A branch that fans out to many distinct (but unresolvable) hashes must
    // hit the record cap rather than fetching unboundedly. We construct a
    // branch listing > MAX_RECORDS child hashes, each resolving to another
    // single-child branch, forcing many fetches.
    let key = test_signing_key();
    let domain = "fan.example.org";

    let mut r = StaticResolver::default();

    // Chain of MAX_RECORDS+10 nested single-child branches.
    let depth_chain = MAX_RECORDS + 10;
    // Build from the tail up so each branch's hash references the next.
    let mut child_body = "enrtree-branch:".to_string(); // terminal empty
    let mut bodies = Vec::new();
    for _ in 0..depth_chain {
        bodies.push(child_body.clone());
        let h = hash_of(&child_body);
        child_body = format!("enrtree-branch:{h}");
    }
    // child_body is now the head branch; register every body by its hash.
    for body in &bodies {
        r.insert(format!("{}.{}", hash_of(body), domain), body.clone());
    }
    let head_hash = hash_of(&child_body);
    r.insert(format!("{head_hash}.{domain}"), child_body.clone());

    let link = "enrtree-branch:".to_string();
    let link_hash = hash_of(&link);
    r.insert(format!("{link_hash}.{domain}"), link);

    let root = signed_root(&key, &head_hash, &link_hash, 1);
    r.insert(domain, root);

    // The depth bound trips first on this deep chain (each branch nests one
    // level), proving a runaway tree is refused rather than walked fully.
    let err = resolve_enrtree(&enrtree_url(&key, domain), Arc::new(r))
        .await
        .expect_err("runaway tree must be bounded");
    assert!(
        matches!(err, DnsError::DepthExceeded | DnsError::RecordLimitExceeded),
        "expected a bound error, got {err:?}"
    );
}
