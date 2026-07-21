// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! secp256k1 root facade with ECDSA routed through the operation layer.

use crypto_core::{Algorithm, CryptoError, SignatureOperation};
use zeroize::Zeroizing;

use crate::signature_error::{
    crypto_error_from_bip340_operation_error, crypto_error_from_operation_error,
};

pub use crypto_secp256k1::{
    decode_bip340_schnorr_public_key, decode_public_key, decompress_public_key,
    encode_bip340_schnorr_public_key, encode_public_key, secp256k1_ecdsa_der_to_jose_signature,
    secp256k1_ecdsa_jose_signature_to_der, BIP340_SCHNORR_AUX_RAND_LEN, BIP340_SCHNORR_MESSAGE_LEN,
    BIP340_SCHNORR_PUBLIC_KEY_LEN, BIP340_SCHNORR_SIGNATURE_LEN,
    SECP256K1_ECDSA_JOSE_SIGNATURE_LEN, SECP256K1_SECRET_KEY_LEN,
};

/// Generate a secp256k1 ECDSA keypair through the signature operation owner.
pub fn generate_secp256k1_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::generate_key_pair(Algorithm::Secp256k1)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Reconstruct a secp256k1 ECDSA keypair from a validated 32-byte scalar.
pub fn generate_secp256k1_keypair_from_secret_key(
    secret_key: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::derive_key_pair(Algorithm::Secp256k1, secret_key)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Sign a message with secp256k1 ECDSA and return a DER-encoded signature.
pub fn sign_secp256k1(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crate::operations::signature::sign(Algorithm::Secp256k1, secret_key, message)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Sign, error))
}

/// Verify a DER-encoded secp256k1 ECDSA signature.
pub fn verify_secp256k1(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify(Algorithm::Secp256k1, public_key, message, signature)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Verify, error))
}

/// Derive a BIP-340 x-only public key from a secp256k1 secret scalar.
pub fn derive_bip340_schnorr_public_key(secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crate::operations::signature::derive_bip340_public_key(secret_key).map_err(|error| {
        crypto_error_from_bip340_operation_error(SignatureOperation::KeyManagement, error)
    })
}

/// Generate a BIP-340 keypair with a canonical x-only public key.
pub fn generate_bip340_schnorr_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::generate_bip340_key_pair()
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_bip340_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Reconstruct a BIP-340 keypair from a validated secp256k1 secret scalar.
pub fn generate_bip340_schnorr_keypair_from_secret_key(
    secret_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::derive_bip340_key_pair(secret_key)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_bip340_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Sign a 32-byte BIP-340 message with explicit 32-byte auxiliary randomness.
pub fn sign_bip340_schnorr(
    secret_key: &[u8],
    message32: &[u8],
    aux_rand32: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    crate::operations::signature::sign_bip340(secret_key, message32, aux_rand32)
        .map_err(|error| crypto_error_from_bip340_operation_error(SignatureOperation::Sign, error))
}

/// Verify a BIP-340 Schnorr signature over a 32-byte message.
pub fn verify_bip340_schnorr(
    signature: &[u8],
    message32: &[u8],
    public_key_xonly: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify_bip340(signature, message32, public_key_xonly).map_err(
        |error| crypto_error_from_bip340_operation_error(SignatureOperation::Verify, error),
    )
}
