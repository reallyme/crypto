// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! HPKE RFC 9180 known-answer test adapter.
//!
//! Executes the base-mode (`mode = 0`) vectors from the CFRG HPKE draft's
//! `test-vectors.json` against the public single-shot API for the suites
//! ReallyMe exposes: derandomized seal (seeded with the vector's `ikmE`) must
//! reproduce the encapsulated key and first ciphertext, and open must recover
//! the plaintext. Vectors for unsupported suites, non-base modes, and the
//! export-only AEAD (`0xffff`) are skipped. Vendored via
//! `scripts/vendor_external_vectors.mjs`; ignored by default.

use crypto_hpke::{
    open_base, seal_base_derand, HpkeDerandSealRequest, HpkeOpenRequest, HpkeSuite,
    HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM, HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
    HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM, HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_json, AuditError};
use serde::Deserialize;

const BASE_MODE: u32 = 0;

#[derive(Deserialize)]
struct HpkeVector {
    mode: u32,
    kem_id: u32,
    kdf_id: u32,
    aead_id: u32,
    info: String,
    #[serde(rename = "pkRm")]
    pk_rm: String,
    #[serde(rename = "skRm")]
    sk_rm: String,
    #[serde(rename = "ikmE")]
    ikm_e: String,
    enc: String,
    encryptions: Vec<HpkeEncryption>,
}

#[derive(Deserialize)]
struct HpkeEncryption {
    aad: String,
    ct: String,
    pt: String,
}

#[test]
#[ignore = "vendored RFC 9180 corpus; run via the external-vectors audit workflow after vendoring"]
fn rfc9180_hpke_base_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let vectors: Vec<HpkeVector> = load_json("hpke/rfc9180_test_vectors.json")?;
    let mut executed = 0usize;

    for vector in &vectors {
        if vector.mode != BASE_MODE {
            continue;
        }
        let suite = match suite_for(vector.kem_id, vector.kdf_id, vector.aead_id) {
            Some(suite) => suite,
            None => continue,
        };
        // First encryption uses sequence number 0, which the single-shot API
        // produces; later sequence numbers need an evolving context.
        let encryption = match vector.encryptions.first() {
            Some(encryption) => encryption,
            None => continue,
        };

        let recipient_public_key = hex_bytes(&vector.pk_rm)?;
        let recipient_private_key = hex_bytes(&vector.sk_rm)?;
        let encapsulation_randomness = hex_bytes(&vector.ikm_e)?;
        let info = hex_bytes(&vector.info)?;
        let aad = hex_bytes(&encryption.aad)?;
        let plaintext = hex_bytes(&encryption.pt)?;
        let expected_enc = hex_bytes(&vector.enc)?;
        let expected_ct = hex_bytes(&encryption.ct)?;

        // Derandomized seal reproduces the encapsulated key and ciphertext.
        let sealed = seal_base_derand(&HpkeDerandSealRequest {
            suite,
            recipient_public_key: &recipient_public_key,
            encapsulation_randomness: &encapsulation_randomness,
            info: &info,
            aad: &aad,
            plaintext: &plaintext,
        })
        .map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(&sealed.encapsulated_key, &expected_enc)?;
        assert_bytes_eq(&sealed.ciphertext, &expected_ct)?;

        // Open recovers the plaintext.
        let opened = open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &expected_enc,
            recipient_private_key: &recipient_private_key,
            info: &info,
            aad: &aad,
            ciphertext: &expected_ct,
        })
        .map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(opened.plaintext.as_slice(), &plaintext)?;

        executed = executed
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
    }

    if executed == 0 {
        return Err(AuditError::NoExecutableVectors);
    }
    Ok(())
}

/// Maps RFC 9180 component ids to a ReallyMe suite, or `None` when the suite is
/// outside the public boundary.
fn suite_for(kem_id: u32, kdf_id: u32, aead_id: u32) -> Option<HpkeSuite> {
    match (kem_id, kdf_id, aead_id) {
        (0x0010, 0x0001, 0x0001) => Some(HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM),
        (0x0010, 0x0001, 0x0002) => Some(HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM),
        (0x0012, 0x0003, 0x0002) => Some(HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM),
        (0x0020, 0x0001, 0x0001) => Some(HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM),
        (0x0020, 0x0001, 0x0003) => Some(HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305),
        _ => None,
    }
}
