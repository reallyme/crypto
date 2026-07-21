// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use ml_kem::{
    kem::{Generate, KeyExport},
    ml_kem_768::DecapsulationKey,
    Seed,
};
use zeroize::{Zeroize, Zeroizing};

/// Length in bytes of the ML-KEM-768 decapsulation (secret) key seed.
pub const ML_KEM_768_SECRET_KEY_LEN: usize = 64;

/// Generate a fresh ML-KEM-768 keypair.
///
/// Returns `(encapsulation_key, secret_seed)`; the secret seed is returned in a
/// zeroizing wrapper so it is wiped when the caller drops it.
pub fn generate_ml_kem_768_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let decapsulation_key =
        DecapsulationKey::try_generate().map_err(|_| CryptoError::KemFailure {
            kind: crypto_core::KemFailureKind::KeyGenerationFailed,
        })?;
    let encapsulation_key = decapsulation_key.encapsulation_key();
    // Wipe the temporary stack copy of the seed after moving it to the heap.
    let mut secret_seed = decapsulation_key.to_bytes();
    let secret = Zeroizing::new(secret_seed.as_slice().to_vec());
    secret_seed.zeroize();
    Ok((encapsulation_key.to_bytes().to_vec(), secret))
}

/// Generate an ML-KEM-768 keypair deterministically from a 64-byte FIPS 203
/// seed (`d || z`).
///
/// This is the derandomized counterpart to [`generate_ml_kem_768_keypair`]: it
/// lets a caller supply its own CSPRNG output for cases that must stay
/// reproducible — deterministic test vectors, or a caller-controlled entropy
/// source. The same 64 seed bytes always yield the same keypair.
///
/// Returns `(encapsulation_key, secret_seed)`; the secret seed is the 64 input
/// bytes, in a zeroizing wrapper. Errors if the seed length is wrong.
pub fn generate_ml_kem_768_keypair_from_seed(
    seed: &[u8; ML_KEM_768_SECRET_KEY_LEN],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let ml_seed = Seed::try_from(&seed[..]).map_err(|_| CryptoError::InvalidKey)?;
    let decapsulation_key = DecapsulationKey::from_seed(ml_seed);
    let encapsulation_key = decapsulation_key.encapsulation_key();
    let secret = Zeroizing::new(seed.to_vec());
    Ok((encapsulation_key.to_bytes().to_vec(), secret))
}
