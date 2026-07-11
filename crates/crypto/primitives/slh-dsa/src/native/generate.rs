// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN;
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use slh_dsa::signature::Keypair;
use slh_dsa::{Sha2_128s, SigningKey};
use zeroize::Zeroizing;

fn invalid_key_generation_seed() -> CryptoError {
    CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::KeyManagement,
        kind: SignatureFailureKind::InvalidPrivateKey,
    }
}

/// Generate an SLH-DSA-SHA2-128s keypair.
pub fn generate_slh_dsa_sha2_128s_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let mut rng = rand::rng();
    let signing_key = SigningKey::<Sha2_128s>::new(&mut rng);
    let public_key = signing_key.verifying_key().to_vec();
    let secret_key = Zeroizing::new(signing_key.to_vec());

    Ok((public_key, secret_key))
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
        return Err(invalid_key_generation_seed());
    }

    let signing_key = SigningKey::<Sha2_128s>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
    let public_key = signing_key.verifying_key().to_vec();
    let secret_key = Zeroizing::new(signing_key.to_vec());

    Ok((public_key, secret_key))
}
