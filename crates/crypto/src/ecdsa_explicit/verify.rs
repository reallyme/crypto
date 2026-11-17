// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::has_standard_sec1_encoding;
use ecdsa::signature::hazmat::PrehashVerifier;

use super::{digest::with_digest, CryptoError, EcdsaCurve, EcdsaEncoding, EcdsaInput};

// The backend also accepts compact (0x05) points. All explicit NIST entry
// points must enforce the same wire shapes as their primitive counterparts,
// including fixed-width verification and the private owner's ECDH method.
pub(super) fn validate_public_key_encoding(
    curve: EcdsaCurve,
    public: &[u8],
) -> Result<(), CryptoError> {
    use crypto_core::contract_constants::{p256, p384, p521};

    let (compressed_len, uncompressed_len) = match curve {
        EcdsaCurve::P256 => (
            p256::P256_PUBLIC_KEY_COMPRESSED_LEN,
            p256::P256_PUBLIC_KEY_UNCOMPRESSED_LEN,
        ),
        EcdsaCurve::P384 => (
            p384::P384_PUBLIC_KEY_COMPRESSED_LEN,
            p384::P384_PUBLIC_KEY_UNCOMPRESSED_LEN,
        ),
        EcdsaCurve::P521 => (
            p521::P521_PUBLIC_KEY_COMPRESSED_LEN,
            p521::P521_PUBLIC_KEY_UNCOMPRESSED_LEN,
        ),
        _ => return Ok(()),
    };
    if has_standard_sec1_encoding(public, compressed_len, uncompressed_len) {
        Ok(())
    } else {
        Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    }
}

/// Validate a compressed or uncompressed SEC1 public point for the specified curve.
pub fn validate_public_key(curve: EcdsaCurve, public: &[u8]) -> Result<(), CryptoError> {
    validate_public_key_encoding(curve, public)?;
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
                validate_public_key_encoding(curve, public)?;
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
