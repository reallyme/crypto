// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, RngFailureKind, RngOutputKind};
use zeroize::Zeroize;

use crate::constants::{
    AEAD_NONCE_12_LENGTH, AES_256_GCM_KEY_LENGTH, ARGON2_SALT_16_LENGTH, ARGON2_SALT_32_LENGTH,
    ML_DSA_87_SEED_LENGTH, ML_KEM_1024_SEED_LENGTH,
};
use crate::rng::SecureRandom;
use crate::types::{
    AeadNonce12, Aes256GcmKeyMaterial, Argon2Salt16, Argon2Salt32, MlDsa87Seed, MlKem1024Seed,
    RandomBytes,
};

/// Generates a random 12-byte AEAD nonce from the given secure RNG, returning an
/// error if the RNG fails to provide entropy.
pub fn generate_aead_nonce_12(rng: &mut impl SecureRandom) -> Result<AeadNonce12, CryptoError> {
    let random = generate_bytes::<AEAD_NONCE_12_LENGTH>(rng, RngOutputKind::AeadNonce12)?;
    Ok(AeadNonce12::from_array(random.into_bytes()))
}

/// Generates a random 16-byte Argon2 salt from the given secure RNG, returning
/// an error if the RNG fails to provide entropy.
pub fn generate_argon2_salt_16(rng: &mut impl SecureRandom) -> Result<Argon2Salt16, CryptoError> {
    let random = generate_bytes::<ARGON2_SALT_16_LENGTH>(rng, RngOutputKind::Argon2Salt16)?;
    Ok(Argon2Salt16::from_array(random.into_bytes()))
}

/// Generates a random 32-byte Argon2 salt from the given secure RNG, returning
/// an error if the RNG fails to provide entropy.
pub fn generate_argon2_salt_32(rng: &mut impl SecureRandom) -> Result<Argon2Salt32, CryptoError> {
    let random = generate_bytes::<ARGON2_SALT_32_LENGTH>(rng, RngOutputKind::Argon2Salt32)?;
    Ok(Argon2Salt32::from_array(random.into_bytes()))
}

/// Generates a random AES-256-GCM key from the given secure RNG.
///
/// The returned owner zeroizes on drop.
pub fn generate_aes256_gcm_key(
    rng: &mut impl SecureRandom,
) -> Result<Aes256GcmKeyMaterial, CryptoError> {
    let random = generate_bytes::<AES_256_GCM_KEY_LENGTH>(rng, RngOutputKind::Aes256GcmKey)?;
    Ok(Aes256GcmKeyMaterial::from_array(random.into_bytes()))
}

/// Generates a random ML-KEM-1024 FIPS 203 seed from the given secure RNG.
///
/// The returned owner zeroizes on drop.
pub fn generate_ml_kem_1024_seed(
    rng: &mut impl SecureRandom,
) -> Result<MlKem1024Seed, CryptoError> {
    let random = generate_bytes::<ML_KEM_1024_SEED_LENGTH>(rng, RngOutputKind::MlKem1024Seed)?;
    Ok(MlKem1024Seed::from_array(random.into_bytes()))
}

/// Generates a random ML-DSA-87 FIPS 204 seed from the given secure RNG.
///
/// The returned owner zeroizes on drop.
pub fn generate_ml_dsa_87_seed(rng: &mut impl SecureRandom) -> Result<MlDsa87Seed, CryptoError> {
    let random = generate_bytes::<ML_DSA_87_SEED_LENGTH>(rng, RngOutputKind::MlDsa87Seed)?;
    Ok(MlDsa87Seed::from_array(random.into_bytes()))
}

/// Generates `N` random bytes from the given secure RNG, tagging any error with
/// `kind`. Returns an error if `N` is zero or the RNG fails to provide entropy.
pub fn generate_bytes<const N: usize>(
    rng: &mut impl SecureRandom,
    kind: RngOutputKind,
) -> Result<RandomBytes<N>, CryptoError> {
    if N == 0 {
        return Err(CryptoError::Rng {
            output: kind,
            kind: RngFailureKind::InvalidOutputLength,
        });
    }

    let mut output = [0u8; N];
    if let Err(error) = rng.fill_secure(&mut output, kind) {
        // An RNG implementation may have written some bytes before reporting
        // failure. Clear the partially populated stack buffer before returning
        // so failed generation cannot leave entropy-bearing material behind.
        output.zeroize();
        return Err(error);
    }
    Ok(RandomBytes::from_array(output))
}
