// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! X-Wing-768 known-answer test adapter (IETF CFRG draft vectors).
//!
//! Exercises the full derandomized KEM path against the official
//! `draft-connolly-cfrg-xwing-kem` `spec/test-vectors.json`: key generation from
//! the 32-byte seed reproduces the public key; derandomized encapsulation from
//! the 64-byte encapsulation seed reproduces the ciphertext and shared secret;
//! and decapsulation recovers the shared secret. Vendored via
//! `scripts/vendor_external_vectors.mjs`; ignored by default.

use crypto_x_wing::{
    generate_x_wing_768_keypair_derand, x_wing_768_decapsulate, x_wing_768_encapsulate_derand,
};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_json, AuditError};
use serde::Deserialize;

#[derive(Deserialize)]
struct XWingVector {
    seed: String,
    eseed: String,
    ss: String,
    sk: String,
    pk: String,
    ct: String,
}

#[test]
#[ignore = "vendored X-Wing draft corpus; run via the external-vectors audit workflow after vendoring"]
fn xwing768_draft_vectors_match_public_api() -> Result<(), AuditError> {
    let vectors: Vec<XWingVector> = load_json("xwing/test-vectors.json")?;
    let mut executed = 0usize;

    for vector in &vectors {
        let seed = hex_bytes(&vector.seed)?;
        let secret_key = hex_bytes(&vector.sk)?;
        let encaps_seed = hex_bytes(&vector.eseed)?;
        let expected_pk = hex_bytes(&vector.pk)?;
        let expected_ct = hex_bytes(&vector.ct)?;
        let expected_ss = hex_bytes(&vector.ss)?;

        // Key generation from the seed reproduces the public key.
        let (public_key, _secret) =
            generate_x_wing_768_keypair_derand(&seed).map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(&public_key, &expected_pk)?;

        // Derandomized encapsulation reproduces the ciphertext and shared secret.
        let (ciphertext, shared_secret) = x_wing_768_encapsulate_derand(&public_key, &encaps_seed)
            .map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(&ciphertext, &expected_ct)?;
        assert_bytes_eq(shared_secret.as_slice(), &expected_ss)?;

        // Decapsulation recovers the shared secret.
        let decapsulated =
            x_wing_768_decapsulate(&ciphertext, &secret_key).map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(decapsulated.as_slice(), &expected_ss)?;

        executed = executed
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
    }

    if executed == 0 {
        return Err(AuditError::NoExecutableVectors);
    }
    Ok(())
}
