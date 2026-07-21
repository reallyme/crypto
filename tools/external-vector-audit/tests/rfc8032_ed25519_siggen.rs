// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! RFC 8032 Ed25519 deterministic signature-generation audit adapter.
//!
//! The ACVP EdDSA suite only exercises verification. Ed25519 signing is
//! deterministic, so a broken nonce/hash path can still verify while producing
//! the wrong signature; this adapter closes that gap by asserting the produced
//! signature bytes match the known answer.
//!
//! Consumes the widely used colon-separated `sign.input` corpus, one vector per
//! line: `sk64:pk:msg:sig_and_msg:` where `sk64` is `seed(32) || pk(32)` and the
//! signature is the first 64 bytes of the fourth field. Vendored via
//! `scripts/vendor_external_vectors.mjs`; ignored by default.

use crypto_ed25519::sign_ed25519;
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_text, AuditError};

const SEED_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

#[test]
#[ignore = "vendored RFC 8032 corpus; run via the external-vectors audit workflow after vendoring"]
fn rfc8032_ed25519_siggen_vectors_match_public_signer() -> Result<(), AuditError> {
    let corpus = load_text("rfc8032/ed25519_sign_input.txt")?;
    let mut executed = 0usize;

    for line in corpus.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        let secret_and_public = fields.first().ok_or(AuditError::Shape)?;
        let message_hex = fields.get(2).ok_or(AuditError::Shape)?;
        let signature_and_message = fields.get(3).ok_or(AuditError::Shape)?;

        let secret_and_public = hex_bytes(secret_and_public)?;
        let seed = secret_and_public.get(..SEED_LEN).ok_or(AuditError::Shape)?;
        let message = hex_bytes(message_hex)?;
        let signature_and_message = hex_bytes(signature_and_message)?;
        let expected_signature = signature_and_message
            .get(..SIGNATURE_LEN)
            .ok_or(AuditError::Shape)?;

        let signature = sign_ed25519(seed, &message).map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(&signature, expected_signature)?;
        executed = executed
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
    }

    if executed == 0 {
        return Err(AuditError::NoExecutableVectors);
    }
    Ok(())
}
