// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(feature = "native")]

use crypto_core::{AeadAlgorithm, Algorithm, MacAlgorithm};
use crypto_dispatch::{
    aead_decrypt, aead_encrypt, derive_shared_secret, generate_keypair, kem_decapsulate,
    kem_encapsulate, mac_authenticate, mac_verify, sign, verify, AeadParams, MacParams,
};

const MESSAGE: &[u8] = b"dispatch boundary validation";
const AAD: &[u8] = b"dispatch boundary aad";

#[test]
fn dispatch_rejects_malformed_signature_key_and_signature_lengths() {
    for algorithm in SIGNATURE_ALGORITHMS.iter().copied() {
        let (public_key, secret_key) =
            generate_keypair(algorithm).expect("signature keypair generation must succeed");
        let signature = sign(algorithm, &secret_key, MESSAGE).expect("signature must succeed");

        assert!(
            sign(algorithm, &[], MESSAGE).is_err(),
            "{algorithm:?} must reject an empty signing key"
        );
        assert!(
            verify(algorithm, &[], MESSAGE, &signature).is_err(),
            "{algorithm:?} must reject an empty verification key"
        );
        assert!(
            verify(algorithm, &public_key, MESSAGE, &[]).is_err(),
            "{algorithm:?} must reject an empty signature"
        );
    }
}

#[test]
fn dispatch_rejects_malformed_key_agreement_lengths() {
    for algorithm in KEY_AGREEMENT_ALGORITHMS.iter().copied() {
        let (public_key, secret_key) =
            generate_keypair(algorithm).expect("key agreement keypair generation must succeed");

        assert!(
            derive_shared_secret(algorithm, &[], &public_key).is_err(),
            "{algorithm:?} must reject an empty secret key"
        );
        assert!(
            derive_shared_secret(algorithm, &secret_key, &[]).is_err(),
            "{algorithm:?} must reject an empty public key"
        );
    }
}

#[test]
fn dispatch_rejects_malformed_kem_key_and_ciphertext_lengths() {
    for algorithm in KEM_ALGORITHMS.iter().copied() {
        let (public_key, secret_key) =
            generate_keypair(algorithm).expect("KEM keypair generation must succeed");
        let (_shared_secret, ciphertext) =
            kem_encapsulate(algorithm, &public_key).expect("KEM encapsulation must succeed");

        assert!(
            kem_encapsulate(algorithm, &[]).is_err(),
            "{algorithm:?} must reject an empty public key"
        );
        assert!(
            kem_decapsulate(algorithm, &[], &secret_key).is_err(),
            "{algorithm:?} must reject an empty ciphertext"
        );
        assert!(
            kem_decapsulate(algorithm, &ciphertext, &[]).is_err(),
            "{algorithm:?} must reject an empty secret key"
        );
    }
}

#[test]
fn dispatch_rejects_malformed_aead_key_nonce_and_ciphertext_lengths() {
    for algorithm in AEAD_ALGORITHMS.iter().copied() {
        let key = valid_aead_key();
        let nonce = valid_aead_nonce(algorithm);
        let params = AeadParams {
            key: &key,
            nonce: &nonce,
            aad: AAD,
        };
        let ciphertext = aead_encrypt(algorithm, &params, MESSAGE).expect("AEAD encrypt must work");

        let empty_key_params = AeadParams {
            key: &[],
            nonce: &nonce,
            aad: AAD,
        };
        assert!(
            aead_encrypt(algorithm, &empty_key_params, MESSAGE).is_err(),
            "{algorithm:?} must reject an empty key"
        );

        let empty_nonce_params = AeadParams {
            key: &key,
            nonce: &[],
            aad: AAD,
        };
        assert!(
            aead_encrypt(algorithm, &empty_nonce_params, MESSAGE).is_err(),
            "{algorithm:?} must reject an empty nonce"
        );
        assert!(
            aead_decrypt(algorithm, &params, &[]).is_err(),
            "{algorithm:?} must reject an empty ciphertext"
        );

        let mut tampered = ciphertext;
        tampered[0] ^= 0x01;
        assert!(
            aead_decrypt(algorithm, &params, &tampered).is_err(),
            "{algorithm:?} must fail closed on authentication failure"
        );
    }
}

#[test]
fn dispatch_mac_verification_rejects_wrong_lengths_and_tampering() {
    for algorithm in MAC_ALGORITHMS.iter().copied() {
        let params = MacParams {
            key: b"dispatch boundary mac key",
        };
        let tag = mac_authenticate(algorithm, &params, MESSAGE).expect("MAC must authenticate");

        assert!(
            mac_verify(algorithm, &params, MESSAGE, &[]).is_err(),
            "{algorithm:?} must reject an empty tag"
        );

        let mut tampered = tag;
        tampered[0] ^= 0x01;
        assert!(
            mac_verify(algorithm, &params, MESSAGE, &tampered).is_err(),
            "{algorithm:?} must reject a full-length tampered tag"
        );
    }
}

const SIGNATURE_ALGORITHMS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::P256,
    Algorithm::P384,
    Algorithm::P521,
    Algorithm::Secp256k1,
    Algorithm::MlDsa44,
    Algorithm::MlDsa65,
    Algorithm::MlDsa87,
];

const KEY_AGREEMENT_ALGORITHMS: &[Algorithm] = &[Algorithm::P256, Algorithm::X25519];

const KEM_ALGORITHMS: &[Algorithm] = &[
    Algorithm::MlKem512,
    Algorithm::MlKem768,
    Algorithm::MlKem1024,
    Algorithm::XWing768,
    Algorithm::XWing1024,
];

const AEAD_ALGORITHMS: &[AeadAlgorithm] = &[
    AeadAlgorithm::Aes256Gcm,
    AeadAlgorithm::Aes256GcmSiv,
    AeadAlgorithm::ChaCha20Poly1305,
    AeadAlgorithm::XChaCha20Poly1305,
];

const MAC_ALGORITHMS: &[MacAlgorithm] = &[MacAlgorithm::HmacSha256, MacAlgorithm::HmacSha512];

fn valid_aead_key() -> [u8; 32] {
    [0x42; 32]
}

fn valid_aead_nonce(algorithm: AeadAlgorithm) -> Vec<u8> {
    match algorithm {
        AeadAlgorithm::Aes256Gcm
        | AeadAlgorithm::Aes256GcmSiv
        | AeadAlgorithm::ChaCha20Poly1305 => vec![0x24; 12],
        AeadAlgorithm::XChaCha20Poly1305 => vec![0x24; 24],
    }
}
