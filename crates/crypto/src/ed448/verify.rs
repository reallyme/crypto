// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ed448_goldilocks::{CompressedEdwardsY, EdwardsPoint};
#[cfg(not(all(feature = "ed448-openssl", not(target_arch = "wasm32"))))]
use zeroize::Zeroizing;

#[cfg(not(all(feature = "ed448-openssl", not(target_arch = "wasm32"))))]
use super::transcript;
use super::{require_support, scalar, CryptoError, Ed448Operation, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// Verify exact message bytes with ordinary Ed448 and empty context. Canonical
/// encodings and nontrivial public keys are required; the provider decodes the
/// curve point during verification. The portable verifier follows RFC 8032's
/// cofactored equation and rejects small-order public keys.
#[allow(clippy::op_ref)] // Challenge and signature scalars stay borrowed from clearing owners.
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    require_support(Ed448Operation::Verify)?;
    let public_point =
        decode_point(public).map_err(|_| CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)?;
    if public_point.double().double() == EdwardsPoint::IDENTITY {
        return Err(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY);
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE);
    }
    let r = decode_point(&signature[..PUBLIC_KEY_LEN])?;
    let s = scalar::decode_signature(&signature[PUBLIC_KEY_LEN..])?;
    #[cfg(all(feature = "ed448-openssl", not(target_arch = "wasm32")))]
    {
        use openssl::{
            pkey::{Id, PKey},
            sign::Verifier,
        };
        let _ = (public_point, r, s);
        let public = PKey::public_key_from_raw_bytes(public, Id::ED448)
            .map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
        let mut verifier = Verifier::new_without_digest(&public)
            .map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
        if verifier
            .verify_oneshot(signature, message)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_SIGNATURE)?
        {
            Ok(())
        } else {
            Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
        }
    }
    #[cfg(not(all(feature = "ed448-openssl", not(target_arch = "wasm32"))))]
    {
        let hash = transcript::hash(&[
            transcript::DOMAIN,
            &signature[..PUBLIC_KEY_LEN],
            public,
            message,
        ]);
        let challenge = scalar::reduce(hash.as_ref())?;
        let left = Zeroizing::new((&EdwardsPoint::GENERATOR * &*s).double().double());
        let scaled_public = Zeroizing::new(&public_point * &*challenge);
        let right = Zeroizing::new((&r + &*scaled_public).double().double());
        if *left == *right {
            Ok(())
        } else {
            Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
        }
    }
}

fn decode_point(bytes: &[u8]) -> Result<EdwardsPoint, CryptoError> {
    use core::cmp::Ordering;
    const COORDINATE_LEN: usize = 56;
    const HALF_COORDINATE_LEN: usize = 28;
    const SIGN_BIT: u8 = 0x80;
    // RFC 8032: p = 2^448 - 2^224 - 1, encoded little-endian. These are
    // canonical-byte and small-order checks. Curve arithmetic and point
    // decoding remain in the reviewed verification provider.
    const MODULUS: [u8; COORDINATE_LEN] = {
        let mut bytes = [0xff; COORDINATE_LEN];
        bytes[HALF_COORDINATE_LEN] = 0xfe;
        bytes
    };
    if bytes.len() != PUBLIC_KEY_LEN || bytes[COORDINATE_LEN] & !SIGN_BIT != 0 {
        return Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE);
    }
    if bytes[..COORDINATE_LEN]
        .iter()
        .rev()
        .cmp(MODULUS.iter().rev())
        != Ordering::Less
    {
        return Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE);
    }
    let encoded: [u8; PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;
    // The unchecked decoder only recovers a point. Validate the curve equation
    // and exact canonical encoding here, retaining RFC cofactored verification
    // rather than imposing a different torsion-free acceptance policy.
    let point = Option::<ed448_goldilocks::AffinePoint>::from(
        CompressedEdwardsY(encoded).decompress_unchecked(),
    )
    .ok_or(CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;
    if !bool::from(point.is_on_curve()) || point.compress().to_bytes() != encoded {
        return Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE);
    }
    Ok(point.to_edwards())
}
