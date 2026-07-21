// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Narrow-feature execution and fail-closed coverage for OpenMLS HPKE profiles.

// These assertions prove the intentionally narrow OpenMLS graph. Cargo
// features are additive, so enabling the full `native` aggregate alongside
// `openmls` necessarily makes the other registered components executable.
#![cfg(all(feature = "openmls", not(feature = "native")))]

use crypto_hpke::{
    derive_keypair_from_ikm, open_base, seal_base, HpkeAeadId, HpkeComponentSupport, HpkeError,
    HpkeKdfId, HpkeKemId, HpkeOpenRequest, HpkeSealRequest, HpkeSuite,
    HPKE_MLKEM1024P384_SHAKE256_AES256GCM, HPKE_MLKEM1024_SHAKE256_AES256GCM,
    HPKE_REGISTERED_AEADS, HPKE_REGISTERED_KDFS, HPKE_REGISTERED_KEMS,
    HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
};

const TEST_IKM: &[u8] = b"reallyme-openmls-hpke-feature-test-ikm";
const TEST_INFO: &[u8] = b"reallyme-openmls-hpke-feature-test-info";
const TEST_AAD: &[u8] = b"reallyme-openmls-hpke-feature-test-aad";
const TEST_PLAINTEXT: &[u8] = b"reallyme-openmls-hpke-feature-test-plaintext";

#[test]
fn openmls_feature_exposes_only_selected_hpke_components() {
    let executable_kems: Vec<HpkeKemId> = HPKE_REGISTERED_KEMS
        .into_iter()
        .filter(|kem| kem.support() == HpkeComponentSupport::Executable)
        .collect();
    assert_eq!(
        executable_kems,
        [
            HpkeKemId::MlKem1024,
            HpkeKemId::MlKem1024P384,
            HpkeKemId::XWing,
        ]
    );

    let executable_kdfs: Vec<HpkeKdfId> = HPKE_REGISTERED_KDFS
        .into_iter()
        .filter(|kdf| kdf.support() == HpkeComponentSupport::Executable)
        .collect();
    assert_eq!(
        executable_kdfs,
        [HpkeKdfId::HkdfSha256, HpkeKdfId::Shake256]
    );

    let executable_aeads: Vec<HpkeAeadId> = HPKE_REGISTERED_AEADS
        .into_iter()
        .filter(|aead| aead.support() == HpkeComponentSupport::Executable)
        .collect();
    assert_eq!(
        executable_aeads,
        [HpkeAeadId::Aes256Gcm, HpkeAeadId::ChaCha20Poly1305]
    );
}

#[test]
fn openmls_feature_round_trips_each_selected_profile() -> Result<(), HpkeError> {
    for suite in [
        HPKE_MLKEM1024_SHAKE256_AES256GCM,
        HPKE_MLKEM1024P384_SHAKE256_AES256GCM,
        HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
    ] {
        let keypair = derive_keypair_from_ikm(suite, TEST_IKM)?;
        let sealed = seal_base(&HpkeSealRequest {
            suite,
            recipient_public_key: &keypair.public_key,
            info: TEST_INFO,
            aad: TEST_AAD,
            plaintext: TEST_PLAINTEXT,
        })?;
        let opened = open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &sealed.encapsulated_key,
            recipient_private_key: keypair.private_key(),
            info: TEST_INFO,
            aad: TEST_AAD,
            ciphertext: &sealed.ciphertext,
        })?;
        assert_eq!(opened.plaintext.as_slice(), TEST_PLAINTEXT);
    }
    Ok(())
}

#[test]
fn openmls_feature_rejects_registered_but_disabled_components() {
    let disabled_kem_suite = HpkeSuite::new(
        HpkeKemId::DhKemP256HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes256Gcm,
    );
    assert_eq!(
        disabled_kem_suite.public_key_len(),
        Err(HpkeError::UnsupportedKem)
    );

    let disabled_kdf_suite = HpkeSuite::new(
        HpkeKemId::MlKem1024,
        HpkeKdfId::HkdfSha384,
        HpkeAeadId::Aes256Gcm,
    );
    assert_eq!(
        disabled_kdf_suite.public_key_len(),
        Err(HpkeError::UnsupportedKdf)
    );

    let disabled_aead_suite = HpkeSuite::new(
        HpkeKemId::MlKem1024,
        HpkeKdfId::Shake256,
        HpkeAeadId::Aes128Gcm,
    );
    assert_eq!(
        disabled_aead_suite.public_key_len(),
        Err(HpkeError::UnsupportedAead)
    );
}
