// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Wycheproof secp256k1 ECDSA (SHA-256) audit adapter.
//!
//! ACVP does not cover secp256k1, so this is the primary conformance source for
//! that boundary. Wycheproof supplies DER signatures; the public verifier takes
//! a 64-byte compact `r || s`, so signatures are converted with the library's
//! strict DER→JOSE helper.
//!
//! # Low-S policy
//!
//! ReallyMe deliberately enforces low-S (BIP-62): it rejects a signature whose
//! `s` exceeds n/2. Standard Wycheproof ECDSA, by contrast, marks high-S
//! signatures `valid` because plain ECDSA permits them (this file contains 72
//! such cases). A high-S signature that Wycheproof calls `valid` is therefore
//! *expected to be rejected* here, and this adapter encodes that: a case is
//! expected to verify only when Wycheproof marks it valid AND its `s` is low-S.
//! That turns the malleability gap into a positive check of the low-S policy
//! rather than a spurious mismatch. Vendored via
//! `scripts/vendor_external_vectors.mjs`; ignored by default.

use crypto_secp256k1::{secp256k1_ecdsa_der_to_jose_signature, verify_secp256k1};
use external_vector_audit::support::{hex_bytes, load_json, AuditError};
use external_vector_audit::wycheproof::{WycheproofFile, WycheproofResult};
use serde::Deserialize;

// secp256k1 group order n divided by two; s is low-S iff s <= this value.
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

const ASN1_INTEGER_TAG: u8 = 0x02;
const ASN1_SEQUENCE_TAG: u8 = 0x30;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaGroup {
    public_key: EcdsaPublicKey,
    sha: String,
    tests: Vec<EcdsaCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaPublicKey {
    curve: String,
    uncompressed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaCase {
    msg: String,
    sig: String,
    result: WycheproofResult,
}

#[test]
#[ignore = "vendored Wycheproof corpus; run via the external-vectors audit workflow after vendoring"]
fn wycheproof_ecdsa_secp256k1_sha256_vectors_execute_against_public_api() -> Result<(), AuditError>
{
    let file: WycheproofFile<EcdsaGroup> =
        load_json("wycheproof/ecdsa_secp256k1_sha256_test.json")?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        if group.public_key.curve != "secp256k1" || group.sha != "SHA-256" {
            continue;
        }
        let public_key = hex_bytes(&group.public_key.uncompressed)?;
        for case in &group.tests {
            if case.result == WycheproofResult::Acceptable {
                continue;
            }
            let message = hex_bytes(&case.msg)?;
            let der = hex_bytes(&case.sig)?;
            let accepted = match secp256k1_ecdsa_der_to_jose_signature(&der) {
                Ok(compact) => verify_secp256k1(&compact, &message, &public_key).is_ok(),
                Err(_) => false,
            };

            // A signature must verify only when it is both Wycheproof-valid and
            // low-S; high-S "valid" cases are expected to be rejected here.
            let expected_accept =
                case.result == WycheproofResult::Valid && !signature_is_high_s(&der);
            if accepted != expected_accept {
                return Err(AuditError::Mismatch);
            }

            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        }
    }

    if executed == 0 {
        return Err(AuditError::NoExecutableVectors);
    }
    Ok(())
}

/// Returns true when the DER signature's `s` value exceeds n/2 (high-S).
///
/// A malformed signature (one this parser cannot read) is treated as not-high-S
/// so the verifier's own rejection remains the observed behaviour.
fn signature_is_high_s(der: &[u8]) -> bool {
    match extract_der_s(der) {
        Some(s) => is_greater_than_half_order(&s),
        None => false,
    }
}

/// Extracts the `s` INTEGER contents from a DER `SEQUENCE { INTEGER r, INTEGER s }`.
fn extract_der_s(der: &[u8]) -> Option<Vec<u8>> {
    if der.first().copied()? != ASN1_SEQUENCE_TAG {
        return None;
    }
    let (_, mut index) = read_der_len(der, 1)?;
    // INTEGER r
    if der.get(index).copied()? != ASN1_INTEGER_TAG {
        return None;
    }
    let (r_len, r_body) = read_der_len(der, index.checked_add(1)?)?;
    index = r_body.checked_add(r_len)?;
    // INTEGER s
    if der.get(index).copied()? != ASN1_INTEGER_TAG {
        return None;
    }
    let (s_len, s_body) = read_der_len(der, index.checked_add(1)?)?;
    let end = s_body.checked_add(s_len)?;
    der.get(s_body..end).map(<[u8]>::to_vec)
}

/// Reads a DER definite length starting at `index`, returning `(len, next_index)`.
fn read_der_len(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
    match bytes.get(index).copied()? {
        first @ 0..=0x7f => Some((usize::from(first), index.checked_add(1)?)),
        0x81 => {
            let len = bytes.get(index.checked_add(1)?).copied()?;
            Some((usize::from(len), index.checked_add(2)?))
        }
        _ => None,
    }
}

/// Big-endian magnitude comparison of `s` against n/2.
fn is_greater_than_half_order(s: &[u8]) -> bool {
    let trimmed = match s.iter().position(|byte| *byte != 0) {
        Some(start) => &s[start..],
        None => &[],
    };
    if trimmed.len() > SECP256K1_HALF_ORDER.len() {
        return true;
    }
    let mut padded = [0u8; 32];
    let offset = SECP256K1_HALF_ORDER.len() - trimmed.len();
    padded[offset..].copy_from_slice(trimmed);
    padded > SECP256K1_HALF_ORDER
}
