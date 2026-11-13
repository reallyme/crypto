// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::brainpool_parameters::{bp320, bp512};

use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use elliptic_curve::sec1::ToSec1Point;
use secrecy::SecretSlice;

use super::{key::secret_copy, CryptoError, EcdsaCurve, EcdsaEncoding};

// Each branch resolves a concrete, independently checked RFC 5639 parameter
// set. All operations below use the same existing arithmetic/signature engines.
macro_rules! with_curve {
    ($curve:expr, $curve_type:ident, $body:block) => {
        match $curve {
            EcdsaCurve::BrainpoolP256r1 => {
                type $curve_type = bp256::BrainpoolP256r1;
                $body
            }
            EcdsaCurve::BrainpoolP320r1 => {
                type $curve_type = bp320::BrainpoolP320r1;
                $body
            }
            EcdsaCurve::BrainpoolP384r1 => {
                type $curve_type = bp384::BrainpoolP384r1;
                $body
            }
            EcdsaCurve::BrainpoolP512r1 => {
                type $curve_type = bp512::BrainpoolP512r1;
                $body
            }
            _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
        }
    };
}

pub(super) fn public_from_private(curve: EcdsaCurve, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    with_curve!(curve, C, {
        let key = elliptic_curve::SecretKey::<C>::from_slice(bytes)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)?;
        Ok(key.public_key().to_sec1_point(false).as_bytes().to_vec())
    })
}

pub(super) fn validate_public(curve: EcdsaCurve, bytes: &[u8]) -> Result<(), CryptoError> {
    with_curve!(curve, C, {
        elliptic_curve::PublicKey::<C>::from_sec1_bytes(bytes)
            .map(|_| ())
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    })
}

pub(super) fn fixed_to_der(curve: EcdsaCurve, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    with_curve!(curve, C, {
        ecdsa::Signature::<C>::from_slice(bytes)
            .map(|signature| signature.to_der().as_bytes().to_vec())
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    })
}

pub(super) fn sign(
    curve: EcdsaCurve,
    private: &[u8],
    digest: &[u8],
    encoding: EcdsaEncoding,
) -> Result<Vec<u8>, CryptoError> {
    with_curve!(curve, C, {
        let key = ecdsa::SigningKey::<C>::from_slice(private)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)?;
        let signature: ecdsa::Signature<C> = key
            .sign_prehash(digest)
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        Ok(match encoding {
            EcdsaEncoding::Der => signature.to_der().as_bytes().to_vec(),
            EcdsaEncoding::FixedWidth => signature.to_bytes().to_vec(),
        })
    })
}

pub(super) fn verify(
    curve: EcdsaCurve,
    public: &[u8],
    digest: &[u8],
    signature: &[u8],
    encoding: EcdsaEncoding,
) -> Result<(), CryptoError> {
    with_curve!(curve, C, {
        let key = ecdsa::VerifyingKey::<C>::from_sec1_bytes(public)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
        let signature = match encoding {
            EcdsaEncoding::Der => ecdsa::Signature::<C>::from_der(signature),
            EcdsaEncoding::FixedWidth => ecdsa::Signature::<C>::from_slice(signature),
        }
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;
        key.verify_prehash(digest, &signature)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    })
}

pub(super) fn agree(
    curve: EcdsaCurve,
    private: &[u8],
    public: &[u8],
) -> Result<SecretSlice<u8>, CryptoError> {
    with_curve!(curve, C, {
        let private = elliptic_curve::SecretKey::<C>::from_slice(private)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)?;
        let public = elliptic_curve::PublicKey::<C>::from_sec1_bytes(public)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
        let shared =
            elliptic_curve::ecdh::diffie_hellman(private.to_nonzero_scalar(), public.as_affine());
        secret_copy(shared.raw_secret_bytes().as_slice())
    })
}

#[cfg(test)]
mod field_tests;
