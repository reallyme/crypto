// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! SLH-DSA-SHA2-128s root facade routed through the signature operation layer.

use crypto_core::{Algorithm, CryptoError, SignatureOperation};
use zeroize::Zeroizing;

use crate::signature_error::{
    crypto_error_from_length_overflow, crypto_error_from_operation_error,
};

const SLH_DSA_KEYGEN_SEED_PART_COUNT: usize = 3;

pub use crypto_slh_dsa::{
    decode_slh_dsa_sha2_128s_public_key, encode_slh_dsa_sha2_128s_public_key,
    SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN, SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN,
    SLH_DSA_SHA2_128S_SECRET_KEY_LEN, SLH_DSA_SHA2_128S_SIGNATURE_LEN,
};

/// Generate an SLH-DSA-SHA2-128s keypair through the signature operation owner.
pub fn generate_slh_dsa_sha2_128s_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::generate_key_pair(Algorithm::SlhDsaSha2_128s)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Derive an SLH-DSA-SHA2-128s keypair from the three FIPS 205 keygen seeds.
pub fn derive_slh_dsa_sha2_128s_keypair(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    if sk_seed.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
        || sk_prf.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
        || pk_seed.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
    {
        return Err(CryptoError::InvalidKey);
    }
    let seed_material_capacity = SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
        .checked_mul(SLH_DSA_KEYGEN_SEED_PART_COUNT)
        .ok_or_else(|| crypto_error_from_length_overflow(SignatureOperation::KeyManagement))?;
    let mut seed_material = Zeroizing::new(Vec::with_capacity(seed_material_capacity));
    seed_material.extend_from_slice(sk_seed);
    seed_material.extend_from_slice(sk_prf);
    seed_material.extend_from_slice(pk_seed);
    crate::operations::signature::derive_key_pair(Algorithm::SlhDsaSha2_128s, &seed_material)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
        .map_err(|error| {
            crypto_error_from_operation_error(SignatureOperation::KeyManagement, error)
        })
}

/// Sign `message` with an SLH-DSA-SHA2-128s serialized secret key.
pub fn sign_slh_dsa_sha2_128s(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crate::operations::signature::sign(Algorithm::SlhDsaSha2_128s, secret_key, message)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Sign, error))
}

/// Verify an SLH-DSA-SHA2-128s detached signature.
pub fn verify_slh_dsa_sha2_128s(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify(Algorithm::SlhDsaSha2_128s, public_key, message, signature)
        .map_err(|error| crypto_error_from_operation_error(SignatureOperation::Verify, error))
}
