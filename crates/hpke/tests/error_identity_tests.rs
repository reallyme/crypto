// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical error identity across the HPKE public interfaces.

use crypto_core::CryptoError;
use crypto_hpke::{HpkeError, HpkeKemId};

#[test]
fn hpke_error_is_the_canonical_error_type() {
    fn canonical(error: HpkeError) -> CryptoError {
        error
    }

    let error = HpkeKemId::try_from(0);
    assert_eq!(error, Err(HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM));
    assert_eq!(
        error.err().map(canonical),
        Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}

#[cfg(feature = "base-p256-aes128gcm")]
#[test]
fn injected_entropy_failures_keep_their_canonical_reason() -> Result<(), CryptoError> {
    use crypto_hpke::base_p256::{
        seal_with_rng, P256BaseError, P256BaseRandomError, P256BaseRng, P256RecipientKey,
    };

    struct HardwareUnavailable;
    impl P256BaseRng for HardwareUnavailable {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), P256BaseRandomError> {
            output.fill(0xa5);
            Err(CryptoError::PROVIDER_HARDWARE_UNAVAILABLE)
        }
    }

    fn canonical(error: P256BaseError) -> CryptoError {
        error
    }
    let key = P256RecipientKey::generate_with_rng(&mut HardwareUnavailable);
    assert_eq!(
        key.err().map(canonical),
        Some(CryptoError::PROVIDER_HARDWARE_UNAVAILABLE)
    );
    let public = hex::decode(concat!(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    ))
    .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    assert_eq!(
        seal_with_rng(
            &public,
            b"exact context",
            b"plaintext",
            &mut HardwareUnavailable
        )
        .err()
        .map(canonical),
        Some(CryptoError::PROVIDER_HARDWARE_UNAVAILABLE)
    );
    Ok(())
}
