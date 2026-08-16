//! In-house EIP-1459 DNS node-list resolver (`enrtree://`).
//!
//! The pinned `discv5` 0.10.4 ships **no** enrtree/DNS support (confirmed in the
//! M11 Phase 0 recon), so the Merkle-tree-over-TXT-records protocol from
//! [EIP-1459] is implemented here from scratch:
//!
//! 1. Parse `enrtree://<base32-pubkey>@<domain>` into a compressed secp256k1
//!    public key + DNS domain.
//! 2. Fetch the root TXT record at `<domain>`; parse
//!    `enrtree-root:v1 e=<enr-hash> l=<link-hash> seq=<n> sig=<base64>` and
//!    verify the 65-byte recoverable secp256k1 ECDSA signature over the
//!    keccak256 of the record content (excluding the `sig=` part) against the
//!    URL public key. A bad signature rejects the whole tree.
//! 3. Recursively walk the subtrees: `enrtree-branch:<h1>,<h2>,...` (recurse
//!    into `<hash>.<domain>`), `enr:<base64>` (decode the leaf ENR),
//!    `enrtree://...` (a link to another tree, followed up to the recursion
//!    bound). Each fetched subtree's content is checked against the base32
//!    keccak256 hash that referenced it; a mismatch rejects that subtree.
//!
//! Recursion depth and total record count are bounded ([`MAX_TREE_DEPTH`],
//! [`MAX_RECORDS`]) to stop a malicious tree from exhausting memory, and a
//! visited-set guards against cycles.
//!
//! [EIP-1459]: https://eips.ethereum.org/EIPS/eip-1459

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use hickory_resolver::{Resolver, name_server::TokioConnectionProvider};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};
use tracing::{debug, warn};

use crate::discovery::enr::Enr;

/// Maximum recursion depth through `enrtree-branch` / `enrtree://` links.
///
/// Phase 0 bound. A legitimate tree is shallow; 16 levels is far beyond any
/// real list while still cheap to refuse.
pub const MAX_TREE_DEPTH: usize = 16;

/// Maximum number of TXT records fetched across the entire walk (the DoS guard
/// against an unbounded / cyclic tree). Phase 0 bound.
pub const MAX_RECORDS: usize = 1024;

/// The `enrtree-root:v1` record prefix.
const ROOT_PREFIX: &str = "enrtree-root:v1";
/// The `enrtree-branch:` subtree prefix.
const BRANCH_PREFIX: &str = "enrtree-branch:";
/// The `enr:` leaf prefix.
const ENR_PREFIX: &str = "enr:";
/// The `enrtree://` link / URL prefix.
const LINK_PREFIX: &str = "enrtree://";

/// Errors raised while resolving an `enrtree://` node list.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// The `enrtree://` URL is malformed.
    #[error("malformed enrtree URL: {0}")]
    MalformedUrl(String),

    /// The base32-encoded public key could not be decoded into a valid
    /// compressed secp256k1 point.
    #[error("invalid enrtree public key: {0}")]
    InvalidPublicKey(String),

    /// A TXT lookup against the DNS resolver failed.
    #[error("DNS lookup for {domain:?} failed: {reason}")]
    Lookup {
        /// The domain name that was queried.
        domain: String,
        /// The underlying resolver error rendered as text.
        reason: String,
    },

    /// The queried name returned no usable TXT record.
    #[error("no TXT record at {0:?}")]
    NoTxtRecord(String),

    /// A record had an unrecognised or malformed shape.
    #[error("malformed enrtree record at {name:?}: {detail}")]
    MalformedRecord {
        /// The DNS name the record was fetched from.
        name: String,
        /// What was wrong with the record body.
        detail: String,
    },

    /// The root record signature did not verify against the URL public key.
    /// Security-critical: this rejects the entire tree.
    #[error("enrtree root signature verification failed for {0:?}")]
    RootSignatureInvalid(String),

    /// A fetched subtree's keccak256 hash did not match the referencing hash.
    #[error("subtree hash mismatch at {name:?}: expected {expected}, got {got}")]
    SubtreeHashMismatch {
        /// The DNS name the subtree was fetched from.
        name: String,
        /// The base32 hash that referenced this subtree.
        expected: String,
        /// The base32 hash actually computed from the fetched content.
        got: String,
    },

    /// The recursion-depth bound was exceeded.
    #[error("enrtree recursion depth exceeded {MAX_TREE_DEPTH}")]
    DepthExceeded,

    /// The total-record bound was exceeded.
    #[error("enrtree record count exceeded {MAX_RECORDS}")]
    RecordLimitExceeded,
}

/// An `enrtree://<base32-pubkey>@<domain>` URL.
#[derive(Debug, Clone)]
pub struct EnrTreeUrl {
    /// The signing public key the root record must verify against.
    pub public_key: VerifyingKey,
    /// The DNS domain hosting the node-list tree.
    pub domain: String,
}

impl EnrTreeUrl {
    /// Parse an `enrtree://<base32-pubkey>@<domain>` URL.
    ///
    /// The username component is the base32 (RFC-4648, no padding) encoding of
    /// the compressed 33-byte secp256k1 public key (EIP-1459 §3.2).
    pub fn parse(url: &str) -> Result<Self, DnsError> {
        let rest = url.strip_prefix(LINK_PREFIX).ok_or_else(|| {
            DnsError::MalformedUrl(format!("missing {LINK_PREFIX} scheme: {url}"))
        })?;
        let (pubkey_b32, domain) = rest
            .split_once('@')
            .ok_or_else(|| DnsError::MalformedUrl(format!("missing '@' separator: {url}")))?;
        if domain.is_empty() {
            return Err(DnsError::MalformedUrl(format!("empty domain: {url}")));
        }

        let key_bytes = BASE32_NOPAD
            .decode(pubkey_b32.as_bytes())
            .map_err(|e| DnsError::InvalidPublicKey(format!("base32 decode: {e}")))?;
        // EIP-1459 publishes the compressed (33-byte) SEC1 point.
        let public_key = VerifyingKey::from_sec1_bytes(&key_bytes)
            .map_err(|e| DnsError::InvalidPublicKey(format!("sec1 point: {e}")))?;

        Ok(Self {
            public_key,
            domain: domain.to_string(),
        })
    }
}

/// The parsed body of an `enrtree-root:v1` record.
#[derive(Debug, Clone)]
struct EnrTreeRoot {
    /// Base32 hash of the ENR subtree root.
    enr_root: String,
    /// Base32 hash of the link subtree root.
    link_root: String,
    /// The content over which the signature was computed (everything up to but
    /// excluding ` sig=`).
    signed_content: String,
    /// The 65-byte recoverable secp256k1 signature.
    signature: Vec<u8>,
}

impl EnrTreeRoot {
    /// Parse `enrtree-root:v1 e=<enr-hash> l=<link-hash> seq=<n> sig=<base64>`.
    fn parse(record: &str, name: &str) -> Result<Self, DnsError> {
        let malformed = |detail: String| DnsError::MalformedRecord {
            name: name.to_string(),
            detail,
        };

        if !record.starts_with(ROOT_PREFIX) {
            return Err(malformed(format!("not an {ROOT_PREFIX} record")));
        }

        // The signature covers the record content excluding the `sig=` part.
        // Per EIP-1459 the `sig=` field is last, so the signed content is
        // everything before it (trailing whitespace trimmed).
        let sig_pos = record
            .find(" sig=")
            .ok_or_else(|| malformed("missing sig= field".to_string()))?;
        let signed_content = record[..sig_pos].to_string();
        let sig_b64 = &record[sig_pos + " sig=".len()..];

        let mut enr_root = None;
        let mut link_root = None;
        let mut seq = None;
        for field in signed_content[ROOT_PREFIX.len()..].split_whitespace() {
            if let Some(v) = field.strip_prefix("e=") {
                enr_root = Some(v.to_string());
            } else if let Some(v) = field.strip_prefix("l=") {
                link_root = Some(v.to_string());
            } else if let Some(v) = field.strip_prefix("seq=") {
                seq = Some(v.to_string());
            }
        }

        let enr_root = enr_root.ok_or_else(|| malformed("missing e= field".to_string()))?;
        let link_root = link_root.ok_or_else(|| malformed("missing l= field".to_string()))?;
        let _seq = seq.ok_or_else(|| malformed("missing seq= field".to_string()))?;

        let signature = BASE64URL_NOPAD
            .decode(sig_b64.trim().as_bytes())
            .map_err(|e| malformed(format!("sig base64: {e}")))?;
        if signature.len() != 65 {
            return Err(malformed(format!(
                "signature is {} bytes, expected 65",
                signature.len()
            )));
        }

        Ok(Self {
            enr_root,
            link_root,
            signed_content,
            signature,
        })
    }

    /// Verify the 65-byte recoverable ECDSA signature over keccak256 of the
    /// signed content against `public_key` (EIP-1459 §3.3).
    fn verify_signature(&self, public_key: &VerifyingKey, name: &str) -> Result<(), DnsError> {
        let digest = Keccak256::digest(self.signed_content.as_bytes());

        let sig = Signature::from_slice(&self.signature[..64])
            .map_err(|_| DnsError::RootSignatureInvalid(name.to_string()))?;
        let recovery_id = RecoveryId::from_byte(self.signature[64])
            .ok_or_else(|| DnsError::RootSignatureInvalid(name.to_string()))?;

        let recovered = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, recovery_id)
            .map_err(|_| DnsError::RootSignatureInvalid(name.to_string()))?;

        // Constant 33-byte compressed SEC1 comparison.
        if recovered.to_encoded_point(true) == public_key.to_encoded_point(true) {
            Ok(())
        } else {
            Err(DnsError::RootSignatureInvalid(name.to_string()))
        }
    }
}

/// Async TXT-record source.
///
/// Abstracted behind a trait so the resolution logic is exercised against a
/// hand-built static fixture in tests without touching the live network. The
/// production implementation is [`HickoryTxtResolver`].
#[async_trait]
pub trait TxtResolver: Send + Sync {
    /// Return the TXT record bodies published at `name` (one entry per record;
    /// multi-string records are concatenated).
    async fn txt(&self, name: &str) -> Result<Vec<String>, DnsError>;
}

/// Production [`TxtResolver`] backed by `hickory-resolver`.
pub struct HickoryTxtResolver {
    resolver: Resolver<TokioConnectionProvider>,
}

impl HickoryTxtResolver {
    /// Build a resolver from the system configuration (`/etc/resolv.conf` on
    /// Unix), using the Tokio async runtime.
    pub fn from_system() -> Result<Self, DnsError> {
        let resolver = Resolver::builder_tokio()
            .map_err(|e| DnsError::Lookup {
                domain: "<system-config>".to_string(),
                reason: e.to_string(),
            })?
            .build();
        Ok(Self { resolver })
    }
}

#[async_trait]
impl TxtResolver for HickoryTxtResolver {
    async fn txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        let lookup = self
            .resolver
            .txt_lookup(name.to_string())
            .await
            .map_err(|e| DnsError::Lookup {
                domain: name.to_string(),
                reason: e.to_string(),
            })?;

        let records = lookup
            .iter()
            .map(|txt| {
                // A single TXT record may be split into multiple <=255-byte
                // strings; EIP-1459 entries are reassembled by concatenation.
                let mut buf = Vec::new();
                for chunk in txt.txt_data() {
                    buf.extend_from_slice(chunk);
                }
                String::from_utf8_lossy(&buf).into_owned()
            })
            .collect();
        Ok(records)
    }
}

/// Compute the EIP-1459 subtree hash of a record: the base32 (RFC-4648, no
/// padding) encoding of the keccak256 of the record's UTF-8 content.
///
/// References use an **abbreviated** form (the leading base32 characters), so a
/// fetched subtree matches when its full hash *starts with* the referencing
/// hash.
fn subtree_hash(content: &str) -> String {
    let digest = Keccak256::digest(content.as_bytes());
    BASE32_NOPAD.encode(digest.as_slice())
}

/// Resolve an `enrtree://` URL into the ENRs it advertises.
///
/// `resolver` supplies TXT records (the network in production, a fixture in
/// tests). The root signature is verified before any subtree is walked; a bad
/// signature rejects the whole tree. Subtree-hash mismatches reject only the
/// offending subtree (logged and skipped) so a single tampered branch does not
/// discard an otherwise valid list, while the recursion-depth and record-count
/// bounds cap the work a malicious tree can induce.
pub async fn resolve_enrtree(
    url: &str,
    resolver: Arc<dyn TxtResolver>,
) -> Result<Vec<Enr>, DnsError> {
    let parsed = EnrTreeUrl::parse(url)?;
    let mut ctx = WalkCtx {
        resolver,
        visited: HashSet::new(),
        records_fetched: 0,
        enrs: Vec::new(),
    };
    ctx.walk_tree(&parsed, 0).await?;
    Ok(ctx.enrs)
}

/// Mutable state threaded through the recursive walk.
struct WalkCtx {
    resolver: Arc<dyn TxtResolver>,
    /// Hashes + linked domains already resolved (cycle guard, EIP-1459 §3.5).
    visited: HashSet<String>,
    /// Total TXT records fetched so far (the [`MAX_RECORDS`] DoS guard).
    records_fetched: usize,
    /// Accumulated, successfully decoded ENRs.
    enrs: Vec<Enr>,
}

impl WalkCtx {
    /// Fetch the root of `tree`, verify its signature, and walk its subtree.
    async fn walk_tree(&mut self, tree: &EnrTreeUrl, depth: usize) -> Result<(), DnsError> {
        if depth > MAX_TREE_DEPTH {
            return Err(DnsError::DepthExceeded);
        }
        // De-dup linked trees by domain to avoid re-walking on a cycle.
        if !self.visited.insert(format!("tree:{}", tree.domain)) {
            return Ok(());
        }

        let root_records = self.fetch(&tree.domain).await?;
        let root_text = root_records
            .iter()
            .find(|r| r.starts_with(ROOT_PREFIX))
            .ok_or_else(|| DnsError::NoTxtRecord(tree.domain.clone()))?;

        let root = EnrTreeRoot::parse(root_text, &tree.domain)?;
        // SECURITY: reject the entire tree if the root signature is invalid.
        root.verify_signature(&tree.public_key, &tree.domain)?;
        debug!(domain = %tree.domain, "enrtree root signature verified");

        // Walk the ENR subtree (where `enr:` leaves live) and the link subtree
        // (where `enrtree://` links live). Both are referenced by hash.
        let enr_root = root.enr_root.clone();
        let link_root = root.link_root.clone();
        self.walk_subtree(tree, &enr_root, depth + 1).await?;
        self.walk_subtree(tree, &link_root, depth + 1).await?;
        Ok(())
    }

    /// Resolve `<hash>.<domain>`, verify its content hash, and dispatch on the
    /// record type.
    async fn walk_subtree(
        &mut self,
        tree: &EnrTreeUrl,
        hash: &str,
        depth: usize,
    ) -> Result<(), DnsError> {
        if depth > MAX_TREE_DEPTH {
            return Err(DnsError::DepthExceeded);
        }
        if hash.is_empty() {
            return Ok(());
        }
        // Cycle guard: never resolve the same hash within the same tree twice.
        let visit_key = format!("{}|{hash}", tree.domain);
        if !self.visited.insert(visit_key) {
            return Ok(());
        }

        let name = format!("{hash}.{}", tree.domain);
        let records = self.fetch(&name).await?;
        let content = records
            .into_iter()
            .next()
            .ok_or_else(|| DnsError::NoTxtRecord(name.clone()))?;

        // Verify the fetched content matches the (abbreviated) referencing hash.
        let full_hash = subtree_hash(&content);
        if !full_hash.starts_with(hash) {
            // A single tampered subtree must not poison the whole tree: reject
            // and skip just this branch (EIP-1459 integrity property).
            warn!(
                name = %name,
                expected = %hash,
                got = %full_hash,
                "enrtree subtree hash mismatch; skipping branch"
            );
            return Err(DnsError::SubtreeHashMismatch {
                name,
                expected: hash.to_string(),
                got: full_hash,
            });
        }

        self.dispatch_record(tree, &name, &content, depth).await
    }

    /// Dispatch a verified subtree record on its prefix.
    async fn dispatch_record(
        &mut self,
        tree: &EnrTreeUrl,
        name: &str,
        content: &str,
        depth: usize,
    ) -> Result<(), DnsError> {
        if let Some(list) = content.strip_prefix(BRANCH_PREFIX) {
            for child_hash in list.split(',') {
                let child_hash = child_hash.trim();
                if child_hash.is_empty() {
                    continue;
                }
                // A bad child branch is isolated: log + skip, keep the rest.
                match Box::pin(self.walk_subtree(tree, child_hash, depth + 1)).await {
                    Ok(()) => {}
                    Err(DnsError::SubtreeHashMismatch { .. }) => continue,
                    Err(e @ (DnsError::DepthExceeded | DnsError::RecordLimitExceeded)) => {
                        return Err(e);
                    }
                    Err(e) => {
                        warn!(name = %name, error = %e, "skipping unresolvable subtree branch");
                    }
                }
            }
            Ok(())
        } else if let Some(b64) = content.strip_prefix(ENR_PREFIX) {
            // `enr:` leaf — decode to an ENR. The canonical text encoding the
            // `enr` crate's FromStr accepts is exactly `enr:<base64url>`.
            match content.parse::<Enr>() {
                Ok(enr) => {
                    debug!(name = %name, "decoded enrtree leaf ENR");
                    self.enrs.push(enr);
                }
                Err(e) => {
                    warn!(name = %name, body = %b64, error = %e, "skipping undecodable enr leaf");
                }
            }
            Ok(())
        } else if content.starts_with(LINK_PREFIX) {
            // `enrtree://` link — follow the linked tree (bounded by depth).
            match EnrTreeUrl::parse(content) {
                Ok(linked) => Box::pin(self.walk_tree(&linked, depth + 1)).await,
                Err(e) => {
                    warn!(name = %name, error = %e, "skipping malformed enrtree link");
                    Ok(())
                }
            }
        } else {
            Err(DnsError::MalformedRecord {
                name: name.to_string(),
                detail: format!("unrecognised entry: {content}"),
            })
        }
    }

    /// Fetch TXT records for `name`, enforcing the total-record cap.
    async fn fetch(&mut self, name: &str) -> Result<Vec<String>, DnsError> {
        if self.records_fetched >= MAX_RECORDS {
            return Err(DnsError::RecordLimitExceeded);
        }
        self.records_fetched += 1;
        let records = self.resolver.txt(name).await?;
        if records.is_empty() {
            return Err(DnsError::NoTxtRecord(name.to_string()));
        }
        Ok(records)
    }
}

#[cfg(test)]
mod bootnode_dns;
