// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use ml_kem::{
    kem::Decapsulate,
    ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey},
    Seed, B32,
};
use zeroize::{Zeroize, Zeroizing};

const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;

/// Encapsulate a shared secret to an ML-KEM-768 public key.
///
/// Returns (ciphertext, shared_secret); the shared secret is returned in a
/// zeroizing wrapper so it is wiped when the caller drops it.
pub fn ml_kem_768_encapsulate(
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

    debug_assert_eq!(ss.len(), 32);
    debug_assert_eq!(ct.len(), ML_KEM_768_CIPHERTEXT_LEN);

    // Wipe the temporary stack copy of the shared secret after moving it to
    // the heap.
    let shared_secret = Zeroizing::new(ss.to_vec());
    ss.zeroize();

    Ok((ct.to_vec(), shared_secret))
}

/// Encapsulate to an ML-KEM-768 public key using caller-supplied 32-byte
/// message randomness (FIPS 203 `m`).
///
/// This is the derandomized counterpart to [`ml_kem_768_encapsulate`]: it lets a
/// caller supply its own CSPRNG output for cases that must stay reproducible —
/// deterministic test vectors, or a caller-controlled entropy source. The same
/// public key and 32 randomness bytes always yield the same ciphertext and
/// shared secret.
///
/// Returns (ciphertext, shared_secret); the shared secret is returned in a
/// zeroizing wrapper. Errors if the key or randomness is malformed.
pub fn ml_kem_768_encapsulate_derand(
    public_key: &[u8],
    randomness: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let public_key = ml_kem::Key::<EncapsulationKey>::try_from(public_key)
        .map_err(|_| CryptoError::InvalidKey)?;
    let pk = EncapsulationKey::new(&public_key).map_err(|_| CryptoError::InvalidKey)?;
    let m = Zeroizing::new(B32::try_from(randomness).map_err(|_| CryptoError::InvalidKey)?);

    let (ct, mut ss) = pk.encapsulate_deterministic(&m);

    debug_assert_eq!(ss.len(), 32);
    debug_assert_eq!(ct.len(), ML_KEM_768_CIPHERTEXT_LEN);

    let shared_secret = Zeroizing::new(ss.to_vec());
    ss.zeroize();

    Ok((ct.to_vec(), shared_secret))
}

/// Decapsulate an ML-KEM-768 ciphertext with the secret key seed.
///
/// Returns the shared secret in a zeroizing wrapper so it is wiped when the
/// caller drops it; errors if the key or ciphertext is malformed.
pub fn ml_kem_768_decapsulate(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let secret_seed = Seed::try_from(secret_key).map_err(|_| CryptoError::InvalidKey)?;
    let sk = DecapsulationKey::from_seed(secret_seed);
    let ciphertext =
        Ciphertext::try_from(ciphertext).map_err(|_| CryptoError::InvalidCiphertextLength {
            minimum: ML_KEM_768_CIPHERTEXT_LEN,
            actual: ciphertext.len(),
        })?;

    let mut ss = sk.decapsulate(&ciphertext);
    let shared_secret = Zeroizing::new(ss.to_vec());
    ss.zeroize();
    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::encapsulate_with_rng;
    use crypto_core::{CryptoError, RngFailureKind, RngOutputKind};
    use getrandom::rand_core::{TryCryptoRng, TryRng};

    struct UnavailableEntropy;

    impl TryRng for UnavailableEntropy {
        type Error = getrandom::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(getrandom::Error::UNSUPPORTED)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(getrandom::Error::UNSUPPORTED)
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            // Model an entropy source that modifies its buffer before failing.
            output.fill(0xa5);
            Err(getrandom::Error::UNSUPPORTED)
        }
    }

    impl TryCryptoRng for UnavailableEntropy {}

    struct FixedEntropy;

    impl TryRng for FixedEntropy {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0x5a5a_5a5a)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0x5a5a_5a5a_5a5a_5a5a)
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            output.fill(0x5a);
            Ok(())
        }
    }

    impl TryCryptoRng for FixedEntropy {}

    #[test]
    fn fallible_encapsulation_matches_the_original_provider_algorithm() -> Result<(), CryptoError> {
        use ml_kem::{kem::Encapsulate, ml_kem_768::EncapsulationKey};

        let (public, _) = super::super::keypair::generate_ml_kem_768_keypair_from_seed(&[7; 64])?;
        let encoded = ml_kem::Key::<EncapsulationKey>::try_from(public.as_slice())
            .map_err(|_| CryptoError::InvalidKey)?;
        let key = EncapsulationKey::new(&encoded).map_err(|_| CryptoError::InvalidKey)?;
        // The previous convenience API delegates to this provider path.
        // Equal entropy must produce byte-identical ciphertext and shared keys.
        let (expected_ciphertext, expected_secret) = key.encapsulate_with_rng(&mut FixedEntropy);
        let (ciphertext, secret) = encapsulate_with_rng(&public, &mut FixedEntropy)?;
        assert_eq!(ciphertext, expected_ciphertext.as_slice());
        assert_eq!(secret.as_slice(), expected_secret.as_slice());
        Ok(())
    }

    #[test]
    fn encapsulation_propagates_entropy_failure() -> Result<(), CryptoError> {
        let (public, _) = super::super::keypair::generate_ml_kem_768_keypair_from_seed(&[7; 64])?;
        assert!(matches!(
            encapsulate_with_rng(&public, &mut UnavailableEntropy),
            Err(CryptoError::Rng {
                output: RngOutputKind::Generic,
                kind: RngFailureKind::EntropyUnavailable,
            })
        ));
        Ok(())
    }

    #[test]
    fn malformed_key_is_rejected_before_entropy_is_requested() {
        assert!(matches!(
            encapsulate_with_rng(&[], &mut UnavailableEntropy),
            Err(CryptoError::InvalidKey)
        ));
    }
}
