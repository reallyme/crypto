// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use ml_kem::{
    kem::Decapsulate,
    ml_kem_512::{Ciphertext, DecapsulationKey, EncapsulationKey},
    Seed, B32,
};
use zeroize::{Zeroize, Zeroizing};

const ML_KEM_512_CIPHERTEXT_LEN: usize = 768;

/// Encapsulate a shared secret to an ML-KEM-512 public key.
///
/// Returns (ciphertext, shared_secret); the shared secret is returned in a
/// zeroizing wrapper so it is wiped when the caller drops it.
pub fn ml_kem_512_encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    encapsulate_with_rng(public_key, &mut getrandom::SysRng)
}

fn encapsulate_with_rng(
    public_key: &[u8],
    rng: &mut impl getrandom::rand_core::TryCryptoRng,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let public_key = ml_kem::Key::<EncapsulationKey>::try_from(public_key)
        .map_err(|_| CryptoError::InvalidKey)?;
    let pk = EncapsulationKey::new(&public_key).map_err(|_| CryptoError::InvalidKey)?;

    // The provider's convenience encapsulate() unwraps OS entropy failures.
    // Own and wipe the randomness even if the OS only partially fills it.
    let mut randomness = Zeroizing::new(B32::default());
    rng.try_fill_bytes(randomness.as_mut_slice())
        .map_err(|_| CryptoError::Rng {
            output: crypto_core::RngOutputKind::Generic,
            kind: crypto_core::RngFailureKind::EntropyUnavailable,
        })?;
    let (ct, mut ss) = pk.encapsulate_deterministic(&randomness);

    // Wipe the temporary stack copy of the shared secret after moving it to
    // the heap.
    let shared_secret = Zeroizing::new(ss.to_vec());
    ss.zeroize();

    Ok((ct.to_vec(), shared_secret))
}

/// Encapsulate to an ML-KEM-512 public key using caller-supplied 32-byte
/// message randomness (FIPS 203 `m`).
pub fn ml_kem_512_encapsulate_derand(
    public_key: &[u8],
    randomness: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let public_key = ml_kem::Key::<EncapsulationKey>::try_from(public_key)
        .map_err(|_| CryptoError::InvalidKey)?;
    let pk = EncapsulationKey::new(&public_key).map_err(|_| CryptoError::InvalidKey)?;
    let m = Zeroizing::new(B32::try_from(randomness).map_err(|_| CryptoError::InvalidKey)?);

    let (ct, mut ss) = pk.encapsulate_deterministic(&m);

    let shared_secret = Zeroizing::new(ss.to_vec());
    ss.zeroize();

    Ok((ct.to_vec(), shared_secret))
}

/// Decapsulate an ML-KEM-512 ciphertext with the secret key seed.
///
/// Returns the shared secret in a zeroizing wrapper so it is wiped when the
/// caller drops it; errors if the key or ciphertext is malformed.
pub fn ml_kem_512_decapsulate(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let secret_seed = Seed::try_from(secret_key).map_err(|_| CryptoError::InvalidKey)?;
    let sk = DecapsulationKey::from_seed(secret_seed);
    let ciphertext =
        Ciphertext::try_from(ciphertext).map_err(|_| CryptoError::InvalidCiphertextLength {
            minimum: ML_KEM_512_CIPHERTEXT_LEN,
            actual: ciphertext.len(),
        })?;

    let mut ss = sk.decapsulate(&ciphertext);
    let shared_secret = Zeroizing::new(ss.to_vec());
    ss.zeroize();
    Ok(shared_secret)
}

#[cfg(test)]
#[path = "encapsulate_tests.rs"]
mod tests;
