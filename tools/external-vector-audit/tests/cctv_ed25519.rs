// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! CCTV Ed25519 strict-verification edge-case vectors.

use crypto_ed25519::verify_ed25519;
use external_vector_audit::support::{hex_bytes, load_json, AuditError};
use serde::Deserialize;

#[derive(Deserialize)]
struct Ed25519Vector {
    key: String,
    sig: String,
    msg: String,
    flags: Option<Vec<Ed25519Flag>>,
}

#[derive(Deserialize)]
enum Ed25519Flag {
    #[serde(rename = "low_order_A")]
    LowOrderA,
    #[serde(rename = "low_order_R")]
    LowOrderR,
    #[serde(rename = "low_order_component_A")]
    LowOrderComponentA,
    #[serde(rename = "low_order_component_R")]
    LowOrderComponentR,
    #[serde(rename = "low_order_residue")]
    LowOrderResidue,
    #[serde(rename = "non_canonical_A")]
    NonCanonicalA,
    #[serde(rename = "non_canonical_R")]
    NonCanonicalR,
    #[serde(rename = "reencoded_k")]
    ReencodedK,
}

#[test]
fn cctv_ed25519_vectors_match_strict_public_verifier() -> Result<(), AuditError> {
    let vectors: Vec<Ed25519Vector> = load_json("cctv/ed25519/ed25519vectors.json")?;
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for vector in &vectors {
        let public_key = hex_bytes(&vector.key)?;
        let signature = hex_bytes(&vector.sig)?;
        let should_accept = strict_verifier_accepts(vector.flags.as_deref().unwrap_or(&[]));
        let accepted_by_reallyme =
            verify_ed25519(&public_key, vector.msg.as_bytes(), &signature).is_ok();

        if accepted_by_reallyme != should_accept {
            return Err(AuditError::Mismatch);
        }

        if should_accept {
            accepted = accepted
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        } else {
            rejected = rejected
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        }
    }

    if accepted == 0 || rejected == 0 {
        Err(AuditError::NoExecutableVectors)
    } else {
        Ok(())
    }
}

fn strict_verifier_accepts(flags: &[Ed25519Flag]) -> bool {
    flags.iter().all(|flag| {
        matches!(
            flag,
            Ed25519Flag::LowOrderComponentA | Ed25519Flag::LowOrderComponentR
        )
    })
}
