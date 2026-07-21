// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Root dispatch facade.

use crypto_core::{
    AeadAlgorithm, CryptoError, HashAlgorithm, MacAlgorithm, MacFailureKind, MacHash,
};
use zeroize::Zeroizing;

pub use crypto_dispatch::{
    derive_keypair, derive_shared_secret, generate_keypair, generate_multikey_keypair,
    kem_decapsulate, kem_encapsulate, provider_decision, public_key_to_multikey, sign,
    validate_verification_method_multikey, verify, AlgorithmError, FallbackPolicy,
    GeneratedKeypair, KeyCopyBoundary, KeyResidency, ProviderDecision, ProviderDisposition,
    ProviderKind, ProviderLane, ProviderOperation, ProviderOutputPolicy, ProviderPolicyReason,
};

/// Borrowed AEAD inputs for the root operation-backed dispatch facade.
///
/// Key and nonce lengths are validated by the semantic operation owner. The
/// adapter borrows caller buffers and never truncates, pads, or retains them.
pub struct AeadParams<'a> {
    /// Symmetric key bytes borrowed for one AEAD operation.
    pub key: &'a [u8],
    /// Nonce bytes borrowed for one AEAD operation.
    pub nonce: &'a [u8],
    /// Additional authenticated data bound to the ciphertext.
    pub aad: &'a [u8],
}

/// Borrowed MAC inputs for the root operation-backed dispatch facade.
///
/// The operation owner validates the key before authentication or verification;
/// this adapter never truncates, pads, or retains caller-owned key material.
pub struct MacParams<'a> {
    /// Symmetric key bytes borrowed for the duration of one MAC operation.
    pub key: &'a [u8],
}

/// Compute a digest through the operation-layer semantic owner.
pub fn hash_digest(algorithm: HashAlgorithm, message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    crate::operations::hash::digest(algorithm, message).map_err(|error| match error {
        crate::operations::OperationError::Provider {
            reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
        } => AlgorithmError::UnsupportedHashAlgorithm(algorithm),
        _ => AlgorithmError::Crypto(CryptoError::Unsupported),
    })
}

/// Encrypts with an AEAD through the operation-layer semantic owner.
pub fn aead_encrypt(
    algorithm: AeadAlgorithm,
    params: &AeadParams<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, AlgorithmError> {
    crate::operations::aead::seal(algorithm, params.key, params.nonce, params.aad, plaintext)
        .map_err(|error| {
            aead_algorithm_error_from_operation_error(
                algorithm,
                crate::aead_error::AeadOperation::Seal,
                error,
                params.key.len(),
                params.nonce.len(),
                plaintext.len(),
            )
        })
}

/// Decrypts with an AEAD through the operation-layer semantic owner.
pub fn aead_decrypt(
    algorithm: AeadAlgorithm,
    params: &AeadParams<'_>,
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
    crate::operations::aead::open(
        algorithm,
        params.key,
        params.nonce,
        params.aad,
        ciphertext_with_tag,
    )
    .map_err(|error| {
        aead_algorithm_error_from_operation_error(
            algorithm,
            crate::aead_error::AeadOperation::Open,
            error,
            params.key.len(),
            params.nonce.len(),
            ciphertext_with_tag.len(),
        )
    })
}

fn aead_algorithm_error_from_operation_error(
    algorithm: AeadAlgorithm,
    operation: crate::aead_error::AeadOperation,
    error: crate::operations::OperationError,
    key_len: usize,
    nonce_len: usize,
    input_len: usize,
) -> AlgorithmError {
    match error {
        crate::operations::OperationError::Provider {
            reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
        } => AlgorithmError::UnsupportedAeadAlgorithm(algorithm),
        _ => AlgorithmError::Crypto(crate::aead_error::crypto_error_from_operation_error(
            algorithm, operation, error, key_len, nonce_len, input_len,
        )),
    }
}

/// Computes a MAC tag through the operation-layer semantic owner.
pub fn mac_authenticate(
    algorithm: MacAlgorithm,
    params: &MacParams<'_>,
    message: &[u8],
) -> Result<Vec<u8>, AlgorithmError> {
    crate::operations::mac::authenticate(algorithm, params.key, message)
        .map_err(|error| mac_algorithm_error_from_operation_error(algorithm, error))
}

/// Verifies a MAC tag through the operation-layer semantic owner.
pub fn mac_verify(
    algorithm: MacAlgorithm,
    params: &MacParams<'_>,
    message: &[u8],
    tag: &[u8],
) -> Result<(), AlgorithmError> {
    crate::operations::mac::verify(algorithm, params.key, message, tag)
        .map_err(|error| mac_algorithm_error_from_operation_error(algorithm, error))
}

fn mac_algorithm_error_from_operation_error(
    algorithm: MacAlgorithm,
    error: crate::operations::OperationError,
) -> AlgorithmError {
    let kind = match error {
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidKey,
        } => MacFailureKind::InvalidKeyLength,
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidLength,
        } => MacFailureKind::InvalidTagLength,
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::VerificationFailed,
        } => MacFailureKind::VerificationFailed,
        crate::operations::OperationError::Provider {
            reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
        } => return AlgorithmError::UnsupportedMacAlgorithm(algorithm),
        _ => MacFailureKind::BackendFailure,
    };

    AlgorithmError::Crypto(CryptoError::Mac {
        hash: mac_hash(algorithm),
        kind,
    })
}

fn mac_hash(algorithm: MacAlgorithm) -> MacHash {
    match algorithm {
        MacAlgorithm::HmacSha256 => MacHash::Sha2_256,
        MacAlgorithm::HmacSha384 => MacHash::Sha2_384,
        MacAlgorithm::HmacSha512 => MacHash::Sha2_512,
    }
}
