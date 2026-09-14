// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
    use ml_kem::{kem::Encapsulate, ml_kem_1024::EncapsulationKey};

    let (public, _) = super::super::keypair::generate_ml_kem_1024_keypair_from_seed(&[7; 64])?;
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
    let (public, _) = super::super::keypair::generate_ml_kem_1024_keypair_from_seed(&[7; 64])?;
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
