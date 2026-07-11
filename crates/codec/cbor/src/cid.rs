// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use cid::Cid;
use multihash::Multihash;
use multihash_codetable::{Code, MultihashDigest};
use sha2::{Digest, Sha256};

/// dag-cbor multicodec code (IPLD)
pub const DAG_CBOR_CODEC: u64 = 0x71;

/// Hash output for sha2-256
pub type ContentHash = [u8; 32];

/// Multihash envelope size used by the CID stack for sha2-256 digests.
pub type DagCborMultihash = Multihash<64>;

/// Returns the raw sha2-256 digest of `bytes`.
pub fn sha2_256_content_hash(bytes: &[u8]) -> ContentHash {
    Sha256::digest(bytes).into()
}

/// Returns a sha2-256 multihash of `bytes` for use in a CID.
pub fn dag_cbor_multihash(bytes: &[u8]) -> DagCborMultihash {
    Code::Sha2_256.digest(bytes)
}

/// Computes the CIDv1 (dag-cbor, sha2-256) of `bytes` as a lowercase string.
pub fn compute_cid_dag_cbor(bytes: &[u8]) -> String {
    let hash = dag_cbor_multihash(bytes);
    let cid = Cid::new_v1(DAG_CBOR_CODEC, hash);
    cid.to_string().to_lowercase()
}

/// Recomputes the CID of `bytes` and compares it to `cid_str`.
///
/// Returns whether they match (case-insensitively), plus the expected and
/// actual (lowercased) CID strings.
pub fn verify_dag_cbor_cid(cid_str: &str, bytes: &[u8]) -> (bool, String, String) {
    let expected = compute_cid_dag_cbor(bytes);
    let actual = cid_str.to_lowercase();
    (expected == actual, expected, actual)
}

/// Returns whether `s` parses as a valid CID string.
pub fn is_valid_cid_string(s: &str) -> bool {
    Cid::try_from(s).is_ok()
}

/// Parses `s` as a CID, returning `None` if it is not a valid CID string.
pub fn try_parse_cid(s: &str) -> Option<Cid> {
    Cid::try_from(s).ok()
}
