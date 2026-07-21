// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
use crypto_core::{
    AeadAlgorithm, AeadBackend, AeadFailureKind, Algorithm, CryptoError, HashAlgorithm,
    MacAlgorithm, MacFailureKind, MacHash, SignatureBackend, SignatureOperation,
};

#[test]
fn signature_algorithms_are_correct() {
    assert!(Algorithm::Ed25519.is_signature());
    assert!(Algorithm::P256.is_signature());
    assert!(Algorithm::P384.is_signature());
    assert!(Algorithm::P521.is_signature());
    assert!(Algorithm::MlDsa44.is_signature());
    assert!(Algorithm::MlDsa65.is_signature());
    assert!(Algorithm::MlDsa87.is_signature());
    assert!(Algorithm::SlhDsaSha2_128s.is_signature());
    assert!(!Algorithm::X25519.is_signature());
}

#[test]
fn key_agreement_algorithms_are_correct() {
    assert!(Algorithm::X25519.is_key_agreement());
    assert!(Algorithm::MlKem512.is_key_agreement());
    assert!(Algorithm::MlKem768.is_key_agreement());
    assert!(Algorithm::MlKem1024.is_key_agreement());
    assert!(Algorithm::XWing768.is_key_agreement());
    assert!(!Algorithm::Ed25519.is_key_agreement());
}

#[test]
fn algorithm_string_mappings_are_stable() {
    assert_eq!(Algorithm::Ed25519.as_str(), "Ed25519");
    assert_eq!(Algorithm::P256.as_str(), "P-256");
    assert_eq!(Algorithm::P384.as_str(), "P-384");
    assert_eq!(Algorithm::P521.as_str(), "P-521");
    assert_eq!(Algorithm::MlDsa44.as_str(), "ML-DSA-44");
    assert_eq!(Algorithm::MlDsa65.as_str(), "ML-DSA-65");
    assert_eq!(Algorithm::MlDsa87.as_str(), "ML-DSA-87");
    assert_eq!(Algorithm::SlhDsaSha2_128s.as_str(), "SLH-DSA-SHA2-128s");
    assert_eq!(Algorithm::MlKem512.as_str(), "ML-KEM-512");
    assert_eq!(Algorithm::XWing768.as_str(), "X-Wing-768");
}

#[test]
fn aead_algorithm_string_mapping_is_stable() {
    assert_eq!(AeadAlgorithm::Aes256Gcm.as_str(), "AES-256-GCM");
}

#[test]
fn hash_algorithm_string_mapping_is_stable() {
    assert_eq!(HashAlgorithm::Sha2_384.as_str(), "SHA2-384");
    assert_eq!(HashAlgorithm::Sha2_512.as_str(), "SHA2-512");
    assert_eq!(HashAlgorithm::Sha3_224.as_str(), "SHA3-224");
    assert_eq!(HashAlgorithm::Sha3_256.as_str(), "SHA3-256");
    assert_eq!(HashAlgorithm::Sha3_384.as_str(), "SHA3-384");
    assert_eq!(HashAlgorithm::Sha3_512.as_str(), "SHA3-512");
}

#[test]
fn mac_algorithm_string_mapping_is_stable() {
    assert_eq!(MacAlgorithm::HmacSha256.as_str(), "HMAC-SHA-256");
    assert_eq!(MacAlgorithm::HmacSha384.as_str(), "HMAC-SHA-384");
    assert_eq!(MacAlgorithm::HmacSha512.as_str(), "HMAC-SHA-512");
}

#[test]
fn typed_aead_error_taxonomy_is_stable() {
    let error = CryptoError::AeadDecrypt {
        backend: AeadBackend::Swift,
        kind: AeadFailureKind::AuthenticationFailed,
    };
    assert_eq!(
        error.to_string(),
        "AEAD decryption failed in swift backend: authentication failed"
    );
}

#[test]
fn typed_signature_error_taxonomy_is_stable() {
    let error = CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Verify,
        kind: crypto_core::SignatureFailureKind::InvalidSignature,
    };
    assert_eq!(
        error.to_string(),
        "signature failed in native backend during verify: invalid signature"
    );
}

#[test]
fn typed_mac_error_taxonomy_is_stable() {
    let error = CryptoError::Mac {
        hash: MacHash::Sha2_512,
        kind: MacFailureKind::VerificationFailed,
    };
    assert_eq!(
        error.to_string(),
        "HMAC failed for SHA-512: verification failed"
    );
}
