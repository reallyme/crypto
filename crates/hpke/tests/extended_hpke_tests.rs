// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(feature = "native")]

use crypto_hpke::{
    derive_keypair, keygen, open_base, open_psk, receiver_export, seal_base, seal_psk,
    sender_export, HpkeAeadId, HpkeError, HpkeKdfId, HpkeOpenRequest, HpkePskOpenRequest,
    HpkePskSealRequest, HpkeReceiverExportRequest, HpkeSealRequest, HpkeSenderExportRequest,
    HpkeSuite, HPKE_MLKEM1024P384_SHAKE256_AES256GCM, HPKE_MLKEM1024_SHAKE256_AES256GCM,
    HPKE_MLKEM512_HKDF_SHA256_AES128GCM, HPKE_MLKEM768_SHAKE256_AES256GCM,
    HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
};

const INFO: &[u8] = b"reallyme-hpke-v0.3";
const AAD: &[u8] = b"reallyme-hpke-aad";
const PLAINTEXT: &[u8] = b"confidential hpke payload";
const EXPORTER_CONTEXT: &[u8] = b"reallyme-hpke-exporter";
const PSK: [u8; 32] = [0x5a; 32];
const PSK_ID: &[u8] = b"deployment-key-2026";

#[test]
fn every_executable_kem_roundtrips_through_a_reviewed_suite() {
    for suite in [
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemP256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes256Gcm,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemP384HkdfSha384,
            HpkeKdfId::HkdfSha384,
            HpkeAeadId::Aes256Gcm,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemP521HkdfSha512,
            HpkeKdfId::HkdfSha512,
            HpkeAeadId::Aes256Gcm,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemSecp256k1HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes256Gcm,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemX25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::ChaCha20Poly1305,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemX448HkdfSha512,
            HpkeKdfId::HkdfSha512,
            HpkeAeadId::Aes256Gcm,
        ),
        HPKE_MLKEM512_HKDF_SHA256_AES128GCM,
        HPKE_MLKEM768_SHAKE256_AES256GCM,
        HPKE_MLKEM1024_SHAKE256_AES256GCM,
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::MlKem768P256,
            HpkeKdfId::Shake256,
            HpkeAeadId::Aes256Gcm,
        ),
        HPKE_MLKEM1024P384_SHAKE256_AES256GCM,
        HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
    ] {
        assert_base_roundtrip(suite);
    }
}

#[test]
fn deterministic_key_derivation_is_stable_for_all_executable_kems() {
    let suites = [
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemP256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes256Gcm,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemP384HkdfSha384,
            HpkeKdfId::HkdfSha384,
            HpkeAeadId::Aes256Gcm,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemP521HkdfSha512,
            HpkeKdfId::HkdfSha512,
            HpkeAeadId::Aes256Gcm,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemSecp256k1HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes256Gcm,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemX25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::ChaCha20Poly1305,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemX448HkdfSha512,
            HpkeKdfId::HkdfSha512,
            HpkeAeadId::Aes256Gcm,
        ),
        HPKE_MLKEM512_HKDF_SHA256_AES128GCM,
        HPKE_MLKEM768_SHAKE256_AES256GCM,
        HPKE_MLKEM1024_SHAKE256_AES256GCM,
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::MlKem768P256,
            HpkeKdfId::Shake256,
            HpkeAeadId::Aes256Gcm,
        ),
        HPKE_MLKEM1024P384_SHAKE256_AES256GCM,
        HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
    ];

    for suite in suites {
        let ikm = vec![0x35; suite.private_key_len().expect("supported KEM")];
        let first = derive_keypair(suite, &ikm).expect("first derivation succeeds");
        let second = derive_keypair(suite, &ikm).expect("second derivation succeeds");
        assert_eq!(first.public_key, second.public_key);
        assert_eq!(first.private_key(), second.private_key());
        assert_eq!(
            first.public_key.len(),
            suite.public_key_len().expect("supported KEM")
        );
        assert_eq!(
            first.private_key().len(),
            suite.private_key_len().expect("supported KEM")
        );
    }
}

#[test]
fn keygen_returns_suite_shaped_keys() {
    let suite = HPKE_MLKEM1024P384_SHAKE256_AES256GCM;
    let keypair = keygen(suite).expect("key generation succeeds");
    assert_eq!(
        keypair.public_key.len(),
        suite.public_key_len().expect("supported KEM")
    );
    assert_eq!(
        keypair.private_key().len(),
        suite.private_key_len().expect("supported KEM")
    );
}

#[test]
fn psk_mode_roundtrips_and_rejects_wrong_psk() {
    let suite = HPKE_MLKEM1024_SHAKE256_AES256GCM;
    let keypair = derive_test_keypair(suite);
    let sealed = seal_psk(&HpkePskSealRequest {
        suite,
        recipient_public_key: &keypair.public_key,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
        psk: &PSK,
        psk_id: PSK_ID,
    })
    .expect("PSK sealing succeeds");

    let opened = open_psk(&HpkePskOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: keypair.private_key(),
        info: INFO,
        aad: AAD,
        ciphertext: &sealed.ciphertext,
        psk: &PSK,
        psk_id: PSK_ID,
    })
    .expect("PSK opening succeeds");
    assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);

    let wrong_psk = [0xa5; 32];
    let error = open_psk(&HpkePskOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: keypair.private_key(),
        info: INFO,
        aad: AAD,
        ciphertext: &sealed.ciphertext,
        psk: &wrong_psk,
        psk_id: PSK_ID,
    })
    .err()
    .expect("wrong PSK must fail authentication");
    assert_eq!(error, HpkeError::OpenFailed);
}

#[test]
fn sender_and_receiver_export_match_in_export_only_mode() {
    let suite = HpkeSuite::new(
        crypto_hpke::HpkeKemId::MlKem1024P384,
        HpkeKdfId::HkdfSha384,
        HpkeAeadId::ExportOnly,
    );
    let keypair = derive_test_keypair(suite);
    let sender = sender_export(&HpkeSenderExportRequest {
        suite,
        recipient_public_key: &keypair.public_key,
        info: INFO,
        exporter_context: EXPORTER_CONTEXT,
        output_length: 64,
    })
    .expect("sender export succeeds");
    let receiver = receiver_export(&HpkeReceiverExportRequest {
        suite,
        encapsulated_key: &sender.encapsulated_key,
        recipient_private_key: keypair.private_key(),
        info: INFO,
        exporter_context: EXPORTER_CONTEXT,
        output_length: 64,
    })
    .expect("receiver export succeeds");

    assert_eq!(sender.exporter_secret(), receiver.as_slice());
}

#[test]
fn new_dhkems_support_psk_and_exporter_contracts() {
    for kem in [
        crypto_hpke::HpkeKemId::DhKemSecp256k1HkdfSha256,
        crypto_hpke::HpkeKemId::DhKemX448HkdfSha512,
    ] {
        let kdf = match kem {
            crypto_hpke::HpkeKemId::DhKemSecp256k1HkdfSha256 => HpkeKdfId::HkdfSha256,
            crypto_hpke::HpkeKemId::DhKemX448HkdfSha512 => HpkeKdfId::HkdfSha512,
            _ => continue,
        };
        let suite = HpkeSuite::new(kem, kdf, HpkeAeadId::Aes256Gcm);
        let keypair = derive_test_keypair(suite);
        let sealed = seal_psk(&HpkePskSealRequest {
            suite,
            recipient_public_key: &keypair.public_key,
            info: INFO,
            aad: AAD,
            plaintext: PLAINTEXT,
            psk: &PSK,
            psk_id: PSK_ID,
        })
        .expect("new DHKEM PSK sealing succeeds");
        let opened = open_psk(&HpkePskOpenRequest {
            suite,
            encapsulated_key: &sealed.encapsulated_key,
            recipient_private_key: keypair.private_key(),
            info: INFO,
            aad: AAD,
            ciphertext: &sealed.ciphertext,
            psk: &PSK,
            psk_id: PSK_ID,
        })
        .expect("new DHKEM PSK opening succeeds");
        assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);

        let export_suite = HpkeSuite::new(kem, kdf, HpkeAeadId::ExportOnly);
        let sender = sender_export(&HpkeSenderExportRequest {
            suite: export_suite,
            recipient_public_key: &keypair.public_key,
            info: INFO,
            exporter_context: EXPORTER_CONTEXT,
            output_length: 64,
        })
        .expect("new DHKEM sender export succeeds");
        let receiver = receiver_export(&HpkeReceiverExportRequest {
            suite: export_suite,
            encapsulated_key: &sender.encapsulated_key,
            recipient_private_key: keypair.private_key(),
            info: INFO,
            exporter_context: EXPORTER_CONTEXT,
            output_length: 64,
        })
        .expect("new DHKEM receiver export succeeds");
        assert_eq!(sender.exporter_secret(), receiver.as_slice());
    }
}

#[test]
fn malformed_psk_info_and_export_lengths_are_rejected_before_backend_setup() {
    let suite = HPKE_MLKEM1024_SHAKE256_AES256GCM;
    let keypair = derive_test_keypair(suite);
    let short_psk = [0x11; 31];
    let error = seal_psk(&HpkePskSealRequest {
        suite,
        recipient_public_key: &keypair.public_key,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
        psk: &short_psk,
        psk_id: PSK_ID,
    })
    .err()
    .expect("short PSK must fail");
    assert_eq!(error, HpkeError::InvalidPsk);

    let oversized_info = vec![0_u8; (1_usize << 16) - 5];
    let error = seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: &keypair.public_key,
        info: &oversized_info,
        aad: AAD,
        plaintext: PLAINTEXT,
    })
    .err()
    .expect("oversized info must fail before backend setup");
    assert_eq!(error, HpkeError::InvalidInfoLength);

    let export_only_suite =
        HpkeSuite::new(suite.kem, HpkeKdfId::HkdfSha256, HpkeAeadId::ExportOnly);
    let error = sender_export(&HpkeSenderExportRequest {
        suite: export_only_suite,
        recipient_public_key: &keypair.public_key,
        info: INFO,
        exporter_context: EXPORTER_CONTEXT,
        output_length: 0,
    })
    .err()
    .expect("empty export must fail");
    assert_eq!(error, HpkeError::InvalidExporterLength);

    let error = sender_export(&HpkeSenderExportRequest {
        suite: export_only_suite,
        recipient_public_key: &keypair.public_key,
        info: INFO,
        exporter_context: EXPORTER_CONTEXT,
        output_length: 1_usize << 16,
    })
    .err()
    .expect("oversized SHAKE export must fail");
    assert_eq!(error, HpkeError::InvalidExporterLength);

    let unsafe_backend_combination =
        HpkeSuite::new(suite.kem, HpkeKdfId::Shake256, HpkeAeadId::ExportOnly);
    let error = sender_export(&HpkeSenderExportRequest {
        suite: unsafe_backend_combination,
        recipient_public_key: &keypair.public_key,
        info: INFO,
        exporter_context: EXPORTER_CONTEXT,
        output_length: 32,
    })
    .err()
    .expect("provider panic path must fail closed");
    assert_eq!(error, HpkeError::UnsupportedSuite);
}

fn assert_base_roundtrip(suite: HpkeSuite) {
    let keypair = derive_test_keypair(suite);
    let sealed = seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: &keypair.public_key,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
    })
    .expect("sealing succeeds");
    let opened = open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: keypair.private_key(),
        info: INFO,
        aad: AAD,
        ciphertext: &sealed.ciphertext,
    })
    .expect("opening succeeds");
    assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);
}

fn derive_test_keypair(suite: HpkeSuite) -> crypto_hpke::HpkeKeyPair {
    let ikm = vec![0x73; suite.private_key_len().expect("supported KEM")];
    derive_keypair(suite, &ikm).expect("key derivation succeeds")
}
