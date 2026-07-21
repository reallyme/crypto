// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]
#![allow(missing_docs)]
#![cfg(all(feature = "native", feature = "test-vectors"))]

use crypto_hpke::{
    derive_keypair, open_base, seal_base, seal_base_derand, HpkeDerandSealRequest, HpkeError,
    HpkeOpenRequest, HpkeSealOutput, HpkeSealRequest, HpkeSuite, HPKE_AEAD_NONCE_LEN,
    HPKE_MLKEM1024P384_SHAKE256_AES256GCM, HPKE_MLKEM1024_SHAKE256_AES256GCM,
    HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
};

const INFO: &[u8] = b"reallyme/hpke/nonce-contract/v1";
const AAD: &[u8] = b"authenticated context";
const PLAINTEXT: &[u8] = b"protocol-protected payload";

#[test]
fn hpke_encrypting_aeads_derive_twelve_byte_nonces_internally() {
    assert_eq!(HPKE_AEAD_NONCE_LEN, 12);

    // The public request carries no nonce. HPKE derives its base nonce and
    // per-message nonce from the key schedule, so callers cannot inject one.
    let suite = HPKE_MLKEM1024_SHAKE256_AES256GCM;
    let recipient = recipient(suite);
    let sealed = seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
    })
    .expect("HPKE sealing with an internally derived nonce must succeed");
    assert_eq!(sealed.ciphertext.len(), PLAINTEXT.len() + suite.tag_len());
}

#[test]
fn fresh_encapsulation_randomness_changes_encapsulation_and_ciphertext() {
    let suite = HPKE_MLKEM1024_SHAKE256_AES256GCM;
    let recipient = recipient(suite);
    let first = seal(suite, &recipient.public_key);
    let second = seal(suite, &recipient.public_key);

    assert_ne!(first.encapsulated_key, second.encapsulated_key);
    assert_ne!(first.ciphertext, second.ciphertext);
}

#[test]
fn deterministic_vector_mode_is_stable_for_required_kems() {
    for suite in [
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemSecp256k1HkdfSha256,
            crypto_hpke::HpkeKdfId::HkdfSha256,
            crypto_hpke::HpkeAeadId::Aes256Gcm,
        ),
        HpkeSuite::new(
            crypto_hpke::HpkeKemId::DhKemX448HkdfSha512,
            crypto_hpke::HpkeKdfId::HkdfSha512,
            crypto_hpke::HpkeAeadId::Aes256Gcm,
        ),
        HPKE_MLKEM1024_SHAKE256_AES256GCM,
        HPKE_MLKEM1024P384_SHAKE256_AES256GCM,
        HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
    ] {
        let recipient = recipient(suite);
        let randomness = vec![0x6d; suite.encapsulation_randomness_len().expect("supported KEM")];
        let first = seal_derand(suite, &recipient.public_key, &randomness);
        let second = seal_derand(suite, &recipient.public_key, &randomness);

        assert_eq!(first.encapsulated_key, second.encapsulated_key);
        assert_eq!(first.ciphertext, second.ciphertext);
    }
}

#[test]
fn opening_fails_when_any_bound_hpke_input_changes() {
    let suite = HPKE_MLKEM1024_SHAKE256_AES256GCM;
    let recipient = recipient(suite);
    let sealed = seal(suite, &recipient.public_key);

    let mut changed_encapsulation = sealed.encapsulated_key.clone();
    changed_encapsulation[0] ^= 0x80;
    assert_open_failed(
        suite,
        recipient.private_key(),
        &changed_encapsulation,
        INFO,
        AAD,
        &sealed.ciphertext,
    );

    let mut changed_ciphertext = sealed.ciphertext.clone();
    changed_ciphertext[0] ^= 0x80;
    assert_open_failed(
        suite,
        recipient.private_key(),
        &sealed.encapsulated_key,
        INFO,
        AAD,
        &changed_ciphertext,
    );
    assert_open_failed(
        suite,
        recipient.private_key(),
        &sealed.encapsulated_key,
        b"different info",
        AAD,
        &sealed.ciphertext,
    );
    assert_open_failed(
        suite,
        recipient.private_key(),
        &sealed.encapsulated_key,
        INFO,
        b"different AAD",
        &sealed.ciphertext,
    );
}

fn recipient(suite: HpkeSuite) -> crypto_hpke::HpkeKeyPair {
    let ikm = vec![0x73; suite.private_key_len().expect("supported KEM")];
    derive_keypair(suite, &ikm).expect("deterministic recipient derivation must succeed")
}

fn seal(suite: HpkeSuite, public_key: &[u8]) -> HpkeSealOutput {
    seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: public_key,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
    })
    .expect("HPKE sealing must succeed")
}

fn seal_derand(suite: HpkeSuite, public_key: &[u8], randomness: &[u8]) -> HpkeSealOutput {
    seal_base_derand(&HpkeDerandSealRequest {
        suite,
        recipient_public_key: public_key,
        encapsulation_randomness: randomness,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
    })
    .expect("deterministic HPKE sealing must succeed")
}

fn assert_open_failed(
    suite: HpkeSuite,
    private_key: &[u8],
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) {
    let result = open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key,
        recipient_private_key: private_key,
        info,
        aad,
        ciphertext,
    });
    assert!(matches!(
        result,
        Err(HpkeError::InvalidEncapsulatedKey | HpkeError::OpenFailed)
    ));
}
