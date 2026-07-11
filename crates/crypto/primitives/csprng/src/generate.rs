// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, RngFailureKind, RngOutputKind};

use crate::constants::{AEAD_NONCE_12_LENGTH, ARGON2_SALT_16_LENGTH, ARGON2_SALT_32_LENGTH};
use crate::rng::SecureRandom;
use crate::types::{AeadNonce12, Argon2Salt16, Argon2Salt32, RandomBytes};

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
    rng.fill_secure(&mut output, kind)?;
    Ok(RandomBytes::from_array(output))
}
