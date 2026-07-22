// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use crypto_hpke::{
    HpkeAeadId, HpkeComponentSupport, HpkeError, HpkeKdfId, HpkeKemId, HpkeSuite,
    HPKE_AEAD_AES_256_GCM, HPKE_AEAD_EXPORT_ONLY, HPKE_KDF_HKDF_SHA384, HPKE_KDF_SHAKE256,
    HPKE_KEM_ML_KEM_1024, HPKE_KEM_ML_KEM_1024_P384, HPKE_KEM_X_WING,
    HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM, HPKE_MLKEM1024_HKDF_SHA384_AES256GCM,
    HPKE_REGISTERED_AEADS, HPKE_REGISTERED_KDFS, HPKE_REGISTERED_KEMS,
    HPKE_SECP256K1_PRIVATE_KEY_LEN, HPKE_SECP256K1_PUBLIC_KEY_LEN, HPKE_X448_PRIVATE_KEY_LEN,
    HPKE_X448_PUBLIC_KEY_LEN, MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
    MLS_192_MLKEM1024_AES256GCM_SHA384_P384, MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
};

#[test]
fn required_registry_values_are_stable() {
    assert_eq!(HPKE_KEM_ML_KEM_1024, 0x0042);
    assert_eq!(HPKE_KEM_ML_KEM_1024_P384, 0x0051);
    assert_eq!(HPKE_KEM_X_WING, 0x647a);
    assert_eq!(HPKE_KDF_HKDF_SHA384, 0x0002);
    assert_eq!(HPKE_KDF_SHAKE256, 0x0011);
    assert_eq!(HPKE_AEAD_AES_256_GCM, 0x0002);
    assert_eq!(HPKE_AEAD_EXPORT_ONLY, 0xffff);
    assert_eq!(HPKE_SECP256K1_PUBLIC_KEY_LEN, 65);
    assert_eq!(HPKE_SECP256K1_PRIVATE_KEY_LEN, 32);
    assert_eq!(HPKE_X448_PUBLIC_KEY_LEN, 56);
    assert_eq!(HPKE_X448_PRIVATE_KEY_LEN, 56);
}

#[test]
fn every_exposed_identifier_roundtrips_from_its_wire_value() {
    let kems = [
        HpkeKemId::DhKemP256HkdfSha256,
        HpkeKemId::DhKemP384HkdfSha384,
        HpkeKemId::DhKemP521HkdfSha512,
        HpkeKemId::DhKemCp256HkdfSha256,
        HpkeKemId::DhKemCp384HkdfSha384,
        HpkeKemId::DhKemCp521HkdfSha512,
        HpkeKemId::DhKemSecp256k1HkdfSha256,
        HpkeKemId::DhKemX25519HkdfSha256,
        HpkeKemId::DhKemX448HkdfSha512,
        HpkeKemId::DhKemX25519ElligatorHkdfSha256,
        HpkeKemId::X25519Kyber768Draft00,
        HpkeKemId::MlKem512,
        HpkeKemId::MlKem768,
        HpkeKemId::MlKem1024,
        HpkeKemId::MlKem768P256,
        HpkeKemId::MlKem1024P384,
        HpkeKemId::XWing,
    ];
    for kem in kems {
        assert_eq!(HpkeKemId::try_from(kem as u16), Ok(kem));
    }

    let kdfs = [
        HpkeKdfId::HkdfSha256,
        HpkeKdfId::HkdfSha384,
        HpkeKdfId::HkdfSha512,
        HpkeKdfId::Shake128,
        HpkeKdfId::Shake256,
        HpkeKdfId::TurboShake128,
        HpkeKdfId::TurboShake256,
    ];
    for kdf in kdfs {
        assert_eq!(HpkeKdfId::try_from(kdf as u16), Ok(kdf));
    }

    let aeads = [
        HpkeAeadId::Aes128Gcm,
        HpkeAeadId::Aes256Gcm,
        HpkeAeadId::ChaCha20Poly1305,
        HpkeAeadId::ExportOnly,
    ];
    for aead in aeads {
        assert_eq!(HpkeAeadId::try_from(aead as u16), Ok(aead));
    }
}

#[test]
fn unknown_identifiers_fail_with_component_specific_errors() {
    assert_eq!(HpkeKemId::try_from(0x0000), Err(HpkeError::UnsupportedKem));
    assert_eq!(HpkeKdfId::try_from(0x0000), Err(HpkeError::UnsupportedKdf));
    assert_eq!(
        HpkeAeadId::try_from(0x0000),
        Err(HpkeError::UnsupportedAead)
    );
}

#[test]
fn mls_192_hybrid_profile_uses_registered_hpke_components() {
    let suite = MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384;
    assert_eq!(suite.kem, HpkeKemId::MlKem1024P384);
    assert_eq!(suite.kdf, HpkeKdfId::HkdfSha384);
    assert_eq!(suite.aead, HpkeAeadId::Aes256Gcm);
    assert_eq!(suite.kem_id(), 0x0051);
    assert_eq!(suite.kdf_id(), 0x0002);
}

#[test]
fn mls_profile_aliases_use_the_exact_draft_hpke_components() {
    for suite in [
        MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
        MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
    ] {
        assert_eq!(suite.kem, HpkeKemId::MlKem1024);
        assert_eq!(suite.kdf, HpkeKdfId::HkdfSha384);
        assert_eq!(suite.aead, HpkeAeadId::Aes256Gcm);
        assert_eq!(suite.kem_id(), 0x0042);
        assert_eq!(suite.kdf_id(), 0x0002);
        assert_eq!(suite.aead_id(), 0x0002);
    }

    let hybrid = MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384;
    assert_eq!(hybrid.kem, HpkeKemId::MlKem1024P384);
    assert_eq!(hybrid.kdf, HpkeKdfId::HkdfSha384);
    assert_eq!(hybrid.aead, HpkeAeadId::Aes256Gcm);
    assert_eq!(hybrid.kem_id(), 0x0051);
    assert_eq!(hybrid.kdf_id(), 0x0002);
}

#[test]
fn mls_profile_aliases_match_their_generic_hpke_suites() {
    assert_eq!(
        MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
        HPKE_MLKEM1024_HKDF_SHA384_AES256GCM
    );
    assert_eq!(
        MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
        HPKE_MLKEM1024_HKDF_SHA384_AES256GCM
    );
    assert_eq!(
        MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
        HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM
    );
}

#[test]
fn registered_but_unavailable_kems_remain_typed() {
    for kem in [
        HpkeKemId::DhKemCp256HkdfSha256,
        HpkeKemId::DhKemCp384HkdfSha384,
        HpkeKemId::DhKemCp521HkdfSha512,
        HpkeKemId::DhKemX25519ElligatorHkdfSha256,
        HpkeKemId::X25519Kyber768Draft00,
    ] {
        let suite = HpkeSuite::new(kem, HpkeKdfId::Shake256, HpkeAeadId::Aes256Gcm);
        assert_eq!(suite.public_key_len(), Err(HpkeError::UnsupportedKem));
    }
}

#[test]
fn iana_registry_matrix_is_complete_and_fail_closed() {
    assert_eq!(HPKE_REGISTERED_KEMS.len(), 17);
    assert_eq!(HPKE_REGISTERED_KDFS.len(), 7);
    assert_eq!(HPKE_REGISTERED_AEADS.len(), 4);

    for kem in HPKE_REGISTERED_KEMS {
        assert_eq!(HpkeKemId::try_from(kem as u16), Ok(kem));
    }
    for kdf in HPKE_REGISTERED_KDFS {
        assert_eq!(HpkeKdfId::try_from(kdf as u16), Ok(kdf));
    }
    for aead in HPKE_REGISTERED_AEADS {
        assert_eq!(HpkeAeadId::try_from(aead as u16), Ok(aead));
    }

    let executable_kem_count = usize::from(cfg!(feature = "kem-dh-p256"))
        + usize::from(cfg!(feature = "kem-dh-p384"))
        + usize::from(cfg!(feature = "kem-dh-p521"))
        + usize::from(cfg!(feature = "kem-secp256k1"))
        + usize::from(cfg!(feature = "kem-x25519"))
        + usize::from(cfg!(feature = "kem-x448"))
        + usize::from(cfg!(feature = "kem-ml-kem-512"))
        + usize::from(cfg!(feature = "kem-ml-kem-768"))
        + usize::from(cfg!(feature = "kem-ml-kem-1024"))
        + usize::from(cfg!(feature = "kem-ml-kem-768-p256"))
        + usize::from(cfg!(feature = "kem-ml-kem-1024-p384"))
        + usize::from(cfg!(feature = "kem-x-wing"));
    let executable_kdf_count = usize::from(cfg!(feature = "kdf-hkdf-sha256"))
        + usize::from(cfg!(feature = "kdf-hkdf-sha384"))
        + usize::from(cfg!(feature = "kdf-hkdf-sha512"))
        + usize::from(cfg!(feature = "kdf-shake256"));
    let executable_aead_count = usize::from(cfg!(feature = "aead-aes128-gcm"))
        + usize::from(cfg!(feature = "aead-aes256-gcm"))
        + usize::from(cfg!(feature = "aead-chacha20-poly1305"))
        + usize::from(cfg!(feature = "aead-export-only"));
    assert_eq!(
        HPKE_REGISTERED_KEMS
            .iter()
            .filter(|kem| kem.support() == HpkeComponentSupport::Executable)
            .count(),
        executable_kem_count
    );
    assert_eq!(
        HPKE_REGISTERED_KDFS
            .iter()
            .filter(|kdf| kdf.support() == HpkeComponentSupport::Executable)
            .count(),
        executable_kdf_count
    );
    assert_eq!(
        HPKE_REGISTERED_AEADS
            .iter()
            .filter(|aead| aead.support() == HpkeComponentSupport::Executable)
            .count(),
        executable_aead_count
    );
}

#[test]
fn registered_but_unavailable_kdfs_fail_with_typed_error() {
    for kdf in [
        HpkeKdfId::Shake128,
        HpkeKdfId::TurboShake128,
        HpkeKdfId::TurboShake256,
    ] {
        let suite = HpkeSuite::new(HpkeKemId::MlKem1024, kdf, HpkeAeadId::Aes256Gcm);
        assert_eq!(suite.public_key_len(), Err(HpkeError::UnsupportedKdf));
    }
}
