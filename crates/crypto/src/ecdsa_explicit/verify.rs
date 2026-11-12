// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ecdsa::signature::hazmat::PrehashVerifier;

use super::{digest::with_digest, EcdsaCurve, EcdsaEncoding, EcdsaError, EcdsaInput};

/// Validate an encoded SEC1 public point for the specified curve.
pub fn validate_public_key(curve: EcdsaCurve, public: &[u8]) -> Result<(), EcdsaError> {
    match curve {
        EcdsaCurve::P256 => p256::PublicKey::from_sec1_bytes(public)
            .map(|_| ())
            .map_err(|_| EcdsaError::InvalidPublicKey),
        EcdsaCurve::P384 => p384::PublicKey::from_sec1_bytes(public)
            .map(|_| ())
            .map_err(|_| EcdsaError::InvalidPublicKey),
        EcdsaCurve::P521 => p521::PublicKey::from_sec1_bytes(public)
            .map(|_| ())
            .map_err(|_| EcdsaError::InvalidPublicKey),
        #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
        curve => super::brainpool::validate_public(curve, public),
        #[cfg(not(all(feature = "brainpool-openssl", not(target_arch = "wasm32"))))]
        _ => Err(EcdsaError::UnsupportedCurve),
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
) -> Result<(), EcdsaError> {
    curve.scalar_len()?;
    super::encode::validate_length(curve, signature, encoding)?;
    with_digest(input, |_, digest| {
        macro_rules! verify_curve {
            ($backend:ident) => {{
                let public = $backend::ecdsa::VerifyingKey::from_sec1_bytes(public)
                    .map_err(|_| EcdsaError::InvalidPublicKey)?;
                let signature = match encoding {
                    EcdsaEncoding::Der => $backend::ecdsa::Signature::from_der(signature),
                    EcdsaEncoding::FixedWidth => $backend::ecdsa::Signature::from_slice(signature),
                }
                .map_err(|_| EcdsaError::InvalidSignature)?;
                public
                    .verify_prehash(digest, &signature)
                    .map_err(|_| EcdsaError::InvalidSignature)
            }};
        }
        match curve {
            EcdsaCurve::P256 => verify_curve!(p256),
            EcdsaCurve::P384 => verify_curve!(p384),
            EcdsaCurve::P521 => verify_curve!(p521),
            #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
            curve => super::brainpool::verify(curve, public, digest, signature, encoding),
            #[cfg(not(all(feature = "brainpool-openssl", not(target_arch = "wasm32"))))]
            _ => Err(EcdsaError::UnsupportedCurve),
        }
    })
}
