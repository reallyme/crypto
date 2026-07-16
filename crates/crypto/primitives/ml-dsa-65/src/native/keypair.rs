// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureOperation};
use ml_dsa::{Generate, KeyExport, Keypair, MlDsa65, Seed, SigningKey};
use zeroize::{Zeroize, Zeroizing};

/// Generate an ML-DSA-65 keypair.
///
/// Public key: 1952 bytes
/// Secret key: 32-byte FIPS seed form, in a zeroizing wrapper so it is
/// wiped when the caller drops it
pub fn generate_ml_dsa_65_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let signing_key =
        SigningKey::<MlDsa65>::try_generate().map_err(|_| CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::KeyManagement,
            kind: crypto_core::SignatureFailureKind::KeyGenerationFailed,
        })?;
    let verifying_key = signing_key.verifying_key();

    // Wipe the temporary stack copy of the seed after moving it to the heap.
    let mut seed_stack = signing_key.to_bytes();
    let secret_seed = Zeroizing::new(seed_stack.to_vec());
    seed_stack.zeroize();

    Ok((verifying_key.to_bytes().to_vec(), secret_seed))
}

/// Generate an ML-DSA-65 keypair deterministically from a 32-byte FIPS 204 seed.
pub fn generate_ml_dsa_65_keypair_from_seed(
    seed: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let ml_seed = Seed::try_from(&seed[..]).map_err(|_| CryptoError::InvalidKey)?;
    let signing_key = SigningKey::<MlDsa65>::from_seed(&ml_seed);
    let verifying_key = signing_key.verifying_key();

    Ok((
        verifying_key.to_bytes().to_vec(),
        Zeroizing::new(seed.to_vec()),
    ))
}
