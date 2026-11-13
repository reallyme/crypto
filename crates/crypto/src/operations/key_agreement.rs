// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic owner for raw key-agreement operations.

use crypto_core::Algorithm;
use zeroize::Zeroizing;

use crate::operations::OperationError;
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Raw public/secret keypair returned by a key-agreement key-management operation.
pub struct KeyAgreementKeyPair {
    /// Public key bytes in the algorithm's canonical key-agreement encoding.
    pub public_key: Vec<u8>,
    /// Secret key or seed bytes. The buffer is wiped when dropped.
    pub secret_key: Zeroizing<Vec<u8>>,
}

/// Generates a raw key-agreement keypair.
pub fn generate_key_pair(algorithm: Algorithm) -> Result<KeyAgreementKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyAgreementKeyGeneration);
    ensure_key_agreement_algorithm(algorithm)?;
    crypto_dispatch::generate_keypair(algorithm).map(key_agreement_key_pair)
}

/// Reconstructs a raw key-agreement keypair from seed or scalar material.
pub fn derive_key_pair(
    algorithm: Algorithm,
    secret_key: &[u8],
) -> Result<KeyAgreementKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyAgreementKeyDerivation);
    ensure_key_agreement_algorithm(algorithm)?;
    crypto_dispatch::derive_keypair(algorithm, secret_key).map(key_agreement_key_pair)
}

/// Derives the raw Diffie-Hellman shared secret.
///
/// This operation intentionally returns the primitive shared-secret output
/// without applying a KDF. Protocol layers must bind algorithm, transcript,
/// party, and application context in their own extract/expand step.
pub fn derive_shared_secret(
    algorithm: Algorithm,
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyAgreementSharedSecret);
    ensure_key_agreement_algorithm(algorithm)?;
    crypto_dispatch::derive_shared_secret(algorithm, secret_key, public_key)
}

/// Supports X25519 and NIST-curve raw key agreement.
pub fn is_key_agreement_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::X25519 | Algorithm::P256 | Algorithm::P384 | Algorithm::P521
    )
}

fn ensure_key_agreement_algorithm(algorithm: Algorithm) -> Result<(), OperationError> {
    if is_key_agreement_algorithm(algorithm) {
        Ok(())
    } else {
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

fn key_agreement_key_pair(
    (public_key, secret_key): (Vec<u8>, Zeroizing<Vec<u8>>),
) -> KeyAgreementKeyPair {
    KeyAgreementKeyPair {
        public_key,
        secret_key,
    }
}
