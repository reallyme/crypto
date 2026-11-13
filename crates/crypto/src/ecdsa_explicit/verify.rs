// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ecdsa::signature::hazmat::PrehashVerifier;

use super::{digest::with_digest, CryptoError, EcdsaCurve, EcdsaEncoding, EcdsaInput};

/// Validate an encoded SEC1 public point for the specified curve.
pub fn validate_public_key(curve: EcdsaCurve, public: &[u8]) -> Result<(), CryptoError> {
    match curve {
        EcdsaCurve::P256 => p256::PublicKey::from_sec1_bytes(public)
            .map(|_| ())
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY),
        EcdsaCurve::P384 => p384::PublicKey::from_sec1_bytes(public)
            .map(|_| ())
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY),
        EcdsaCurve::P521 => p521::PublicKey::from_sec1_bytes(public)
            .map(|_| ())
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY),
        #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
        curve => super::brainpool::validate_public(curve, public),
        #[cfg(all(
            feature = "brainpool",
            not(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))
        ))]
        curve => super::portable_brainpool::validate_public(curve, public),
        #[cfg(not(any(
            feature = "brainpool",
            all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
        )))]
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

/// Verify exact message bytes or an explicit prehash, with no normalization or
/// inferred hash. The caller validates certificate OIDs and protocol policy.
pub fn verify(
    curve: EcdsaCurve,
    public: &[u8],
    input: EcdsaInput<'_>,
    signature: &[u8],
    encoding: EcdsaEncoding,
) -> Result<(), CryptoError> {
    curve.scalar_len()?;
    super::encode::validate_length(curve, signature, encoding)?;
    with_digest(input, |_, digest| {
        // Preserve the existing prehash/key error precedence when more than
        // one input is invalid. All providers then consume the same strict
        // codec boundary, without changing the caller's message bytes.
        let fixed;
        let signature = match encoding {
            EcdsaEncoding::Der => {
                validate_public_key(curve, public)?;
                fixed = super::encode::der_to_fixed(curve, signature)?;
                fixed.as_slice()
            }
            EcdsaEncoding::FixedWidth => signature,
        };
        macro_rules! verify_curve {
            ($backend:ident) => {{
                let public = $backend::ecdsa::VerifyingKey::from_sec1_bytes(public)
                    .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
                let signature = $backend::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;
                public
                    .verify_prehash(digest, &signature)
                    .map_err(|_| CryptoError::PRIMITIVE_INVALID_SIGNATURE)
            }};
        }
        match curve {
            EcdsaCurve::P256 => verify_curve!(p256),
            EcdsaCurve::P384 => verify_curve!(p384),
            EcdsaCurve::P521 => verify_curve!(p521),
            #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
            curve => super::brainpool::verify(
                curve,
                public,
                digest,
                signature,
                EcdsaEncoding::FixedWidth,
            ),
            #[cfg(all(
                feature = "brainpool",
                not(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))
            ))]
            curve => super::portable_brainpool::verify(
                curve,
                public,
                digest,
                signature,
                EcdsaEncoding::FixedWidth,
            ),
            #[cfg(not(any(
                feature = "brainpool",
                all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
            )))]
            _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
        }
    })
}
