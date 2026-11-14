// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HPKE RFC 9180 known-answer test adapter.
//!
//! Executes the base-mode (`mode = 0`) vectors from the CFRG HPKE draft's
//! `test-vectors.json` against the public single-shot API for the suites
//! ReallyMe exposes: derandomized seal (seeded with the vector's `ikmE`) must
//! reproduce the encapsulated key and first ciphertext, and open must recover
//! the plaintext. The context-binding test uses independent Base and PSK
//! records from the same corpus and substitutes one input at a time. Vendored
//! via `scripts/vendor_external_vectors.mjs`; ignored by default.

use crypto_hpke::{
    open_base, open_psk, seal_base_derand, HpkeAeadId, HpkeDerandSealRequest, HpkeError, HpkeKdfId,
    HpkeOpenOutput, HpkeOpenRequest, HpkePskOpenRequest, HpkeSuite,
    HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM, HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
    HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM, HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_json, AuditError};
use serde::Deserialize;
use zeroize::Zeroizing;

const BASE_MODE: u32 = 0;
const PSK_MODE: u32 = 1;
const CORPUS: &str = "hpke/rfc9180_test_vectors.json";
const AUDITED_SUITES: [HpkeSuite; 5] = [
    HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM,
    HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
    HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
];

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
    psk: Option<String>,
    psk_id: Option<String>,
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
    let vectors: Vec<HpkeVector> = load_json(CORPUS)?;
    let mut executed = 0usize;

    for vector in &vectors {
        if vector.mode != BASE_MODE {
            continue;
        }
        let suite = match AUDITED_SUITES
            .into_iter()
            .find(|suite| matches_suite(vector, *suite))
        {
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
        let recipient_private_key = Zeroizing::new(hex_bytes(&vector.sk_rm)?);
        let encapsulation_randomness = Zeroizing::new(hex_bytes(&vector.ikm_e)?);
        let info = hex_bytes(&vector.info)?;
        let aad = hex_bytes(&encryption.aad)?;
        let plaintext = Zeroizing::new(hex_bytes(&encryption.pt)?);
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

fn matches_suite(vector: &HpkeVector, suite: HpkeSuite) -> bool {
    vector.kem_id == u32::from(suite.kem_id())
        && vector.kdf_id == u32::from(suite.kdf_id())
        && vector.aead_id == u32::from(suite.aead_id())
}

#[test]
#[ignore = "vendored RFC 9180 corpus; run via the external-vectors audit workflow after vendoring"]
fn rfc9180_hpke_open_binds_context_in_base_and_psk_modes() -> Result<(), AuditError> {
    let vectors: Vec<HpkeVector> = load_json(CORPUS)?;
    for suite in AUDITED_SUITES {
        let base = find_vector(&vectors, BASE_MODE, suite)?;
        let psk = find_vector(&vectors, PSK_MODE, suite)?;
        // Each alternate key is used successfully by the other record under
        // the same KEM and suite, so an invalid key cannot satisfy a negative test.
        if base.pk_rm == psk.pk_rm {
            return Err(AuditError::Shape);
        }
        check_context(base, psk, suite)?;
        check_context(psk, base, suite)?;
    }
    Ok(())
}

fn find_vector(
    vectors: &[HpkeVector],
    mode: u32,
    suite: HpkeSuite,
) -> Result<&HpkeVector, AuditError> {
    vectors
        .iter()
        .find(|vector| vector.mode == mode && matches_suite(vector, suite))
        .ok_or(AuditError::NoExecutableVectors)
}

fn check_context(
    vector: &HpkeVector,
    other_recipient: &HpkeVector,
    suite: HpkeSuite,
) -> Result<(), AuditError> {
    let [first, second, ..] = vector.encryptions.as_slice() else {
        return Err(AuditError::Shape);
    };
    let enc = hex_bytes(&vector.enc)?;
    let private_key = Zeroizing::new(hex_bytes(&vector.sk_rm)?);
    let wrong_private_key = Zeroizing::new(hex_bytes(&other_recipient.sk_rm)?);
    let info = hex_bytes(&vector.info)?;
    let aad = hex_bytes(&first.aad)?;
    let ciphertext = hex_bytes(&first.ct)?;
    let plaintext = Zeroizing::new(hex_bytes(&first.pt)?);
    let psk = match (vector.mode, &vector.psk, &vector.psk_id) {
        (BASE_MODE, None, None) => None,
        (PSK_MODE, Some(psk), Some(id)) => Some((Zeroizing::new(hex_bytes(psk)?), hex_bytes(id)?)),
        _ => return Err(AuditError::Shape),
    };
    let psk = psk
        .as_ref()
        .map(|(key, id)| (key.as_slice(), id.as_slice()));
    let baseline = HpkeOpenRequest {
        suite,
        encapsulated_key: &enc,
        recipient_private_key: &private_key,
        info: &info,
        aad: &aad,
        ciphertext: &ciphertext,
    };
    let opened = open_vector(&baseline, psk).map_err(|_| AuditError::Mismatch)?;
    assert_bytes_eq(opened.plaintext.as_slice(), &plaintext)?;

    // Hold the KEM fixed so the alternate suite can parse the original record.
    let other_kdf = HpkeKdfId::HkdfSha384;
    assert_ne!(suite.kdf, other_kdf);
    let other_aead = if suite.aead == HpkeAeadId::Aes128Gcm {
        HpkeAeadId::Aes256Gcm
    } else {
        HpkeAeadId::Aes128Gcm
    };
    let mut wrong_info = info.clone();
    *wrong_info.first_mut().ok_or(AuditError::Shape)? ^= 1;
    // Use the next upstream AAD value with the sequence-zero record.
    let wrong_aad = hex_bytes(&second.aad)?;
    if aad == wrong_aad || *private_key == *wrong_private_key {
        return Err(AuditError::Shape);
    }
    for (name, changed) in [
        (
            "suite KDF",
            HpkeOpenRequest {
                suite: HpkeSuite {
                    kdf: other_kdf,
                    ..suite
                },
                ..baseline
            },
        ),
        (
            "suite AEAD",
            HpkeOpenRequest {
                suite: HpkeSuite {
                    aead: other_aead,
                    ..suite
                },
                ..baseline
            },
        ),
        (
            "recipient key",
            HpkeOpenRequest {
                recipient_private_key: &wrong_private_key,
                ..baseline
            },
        ),
        (
            "info",
            HpkeOpenRequest {
                info: &wrong_info,
                ..baseline
            },
        ),
        (
            "AAD",
            HpkeOpenRequest {
                aad: &wrong_aad,
                ..baseline
            },
        ),
    ] {
        assert_eq!(
            open_vector(&changed, psk).err(),
            Some(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED),
            "RFC 9180 mode {}, suite {:?}, changed {name}",
            vector.mode,
            suite,
        );
    }
    Ok(())
}

fn open_vector(
    request: &HpkeOpenRequest<'_>,
    psk: Option<(&[u8], &[u8])>,
) -> Result<HpkeOpenOutput, HpkeError> {
    match psk {
        None => open_base(request),
        Some((psk, psk_id)) => open_psk(&HpkePskOpenRequest {
            suite: request.suite,
            encapsulated_key: request.encapsulated_key,
            recipient_private_key: request.recipient_private_key,
            info: request.info,
            aad: request.aad,
            ciphertext: request.ciphertext,
            psk,
            psk_id,
        }),
    }
}
