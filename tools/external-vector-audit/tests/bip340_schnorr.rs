// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! BIP-340 Schnorr verification audit adapter.
//!
//! Executes the official BIP-340 `test-vectors.csv` against the public
//! verifier, covering the standard positive cases and the malleability /
//! invalid-point negative cases. Rows whose message is not 32 bytes (the
//! variable-length extension vectors) are skipped because the public boundary
//! takes a fixed 32-byte message. Vendored via
//! `scripts/vendor_external_vectors.mjs`; ignored by default.

use crypto_secp256k1::{
    verify_bip340_schnorr, BIP340_SCHNORR_MESSAGE_LEN, BIP340_SCHNORR_PUBLIC_KEY_LEN,
    BIP340_SCHNORR_SIGNATURE_LEN,
};
use external_vector_audit::support::{hex_bytes, load_text, AuditError};

#[test]
#[ignore = "vendored BIP-340 corpus; run via the external-vectors audit workflow after vendoring"]
fn bip340_schnorr_verification_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let csv = load_text("bip340/test-vectors.csv")?;
    let mut executed = 0usize;

    for line in csv.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        // index,secret key,public key,aux_rand,message,signature,result,comment
        let public_key_hex = fields.get(2).ok_or(AuditError::Shape)?.trim();
        let message_hex = fields.get(4).ok_or(AuditError::Shape)?.trim();
        let signature_hex = fields.get(5).ok_or(AuditError::Shape)?.trim();
        let expected = match fields.get(6).map(|value| value.trim().to_ascii_uppercase()) {
            Some(ref value) if value == "TRUE" => true,
            Some(ref value) if value == "FALSE" => false,
            _ => return Err(AuditError::Shape),
        };

        let public_key = hex_bytes(public_key_hex)?;
        let message = hex_bytes(message_hex)?;
        let signature = hex_bytes(signature_hex)?;

        // The public boundary is fixed 32-byte messages; skip extension vectors.
        if message.len() != BIP340_SCHNORR_MESSAGE_LEN
            || public_key.len() != BIP340_SCHNORR_PUBLIC_KEY_LEN
            || signature.len() != BIP340_SCHNORR_SIGNATURE_LEN
        {
            continue;
        }

        let accepted = verify_bip340_schnorr(&signature, &message, &public_key).is_ok();
        if accepted != expected {
            return Err(AuditError::Mismatch);
        }
        executed = executed
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
    }

    if executed == 0 {
        return Err(AuditError::NoExecutableVectors);
    }
    Ok(())
}
