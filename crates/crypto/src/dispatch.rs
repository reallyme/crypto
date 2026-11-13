// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Root dispatch facade.

use crypto_core::{AeadAlgorithm, HashAlgorithm, MacAlgorithm};
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
    crate::operations::hash::digest(algorithm, message)
}

/// Encrypts with an AEAD through the operation-layer semantic owner.
pub fn aead_encrypt(
    algorithm: AeadAlgorithm,
    params: &AeadParams<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, AlgorithmError> {
    crate::operations::aead::seal(algorithm, params.key, params.nonce, params.aad, plaintext)
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
}

/// Computes a MAC tag through the operation-layer semantic owner.
pub fn mac_authenticate(
    algorithm: MacAlgorithm,
    params: &MacParams<'_>,
    message: &[u8],
) -> Result<Vec<u8>, AlgorithmError> {
    crate::operations::mac::authenticate(algorithm, params.key, message)
}

/// Verifies a MAC tag through the operation-layer semantic owner.
pub fn mac_verify(
    algorithm: MacAlgorithm,
    params: &MacParams<'_>,
    message: &[u8],
    tag: &[u8],
) -> Result<(), AlgorithmError> {
    crate::operations::mac::verify(algorithm, params.key, message, tag)
}
