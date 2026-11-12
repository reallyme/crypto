// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{require_support, Ed448Error, Ed448Operation};
#[cfg(all(feature = "ed448-openssl", not(target_arch = "wasm32")))]
use super::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// Verify exact message bytes with ordinary Ed448 and empty context. Canonical
/// encodings and nontrivial public keys are required; the provider decodes the
/// curve point during verification. No private-key operation is exposed here.
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Ed448Error> {
    require_support(Ed448Operation::Verify)?;
    #[cfg(all(feature = "ed448-openssl", not(target_arch = "wasm32")))]
    {
        use openssl::{
            pkey::{Id, PKey},
            sign::Verifier,
        };
        validate_encoding(public)?;
        if signature.len() != SIGNATURE_LEN {
            return Err(Ed448Error::InvalidSignature);
        }
        let public = PKey::public_key_from_raw_bytes(public, Id::ED448)
            .map_err(|_| Ed448Error::UnsupportedAlgorithm)?;
        let mut verifier =
            Verifier::new_without_digest(&public).map_err(|_| Ed448Error::UnsupportedAlgorithm)?;
        if verifier
            .verify_oneshot(signature, message)
            .map_err(|_| Ed448Error::InvalidSignature)?
        {
            Ok(())
        } else {
            Err(Ed448Error::InvalidSignature)
        }
    }
    #[cfg(not(all(feature = "ed448-openssl", not(target_arch = "wasm32"))))]
    {
        let _ = (public, message, signature);
        Err(Ed448Error::UnsupportedAlgorithm)
    }
}

#[cfg(all(feature = "ed448-openssl", not(target_arch = "wasm32")))]
fn validate_encoding(public: &[u8]) -> Result<(), Ed448Error> {
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
    const MINUS_ONE: [u8; COORDINATE_LEN] = {
        let mut bytes = MODULUS;
        bytes[0] = 0xfe;
        bytes
    };
    if public.len() != PUBLIC_KEY_LEN || public[COORDINATE_LEN] & !SIGN_BIT != 0 {
        return Err(Ed448Error::InvalidPublicKey);
    }
    let coordinate = &public[..COORDINATE_LEN];
    let is_zero = coordinate.iter().all(|byte| *byte == 0);
    let is_one = coordinate[0] == 1 && coordinate[1..].iter().all(|byte| *byte == 0);
    if coordinate.iter().rev().cmp(MODULUS.iter().rev()) != Ordering::Less
        || is_zero
        || is_one
        || coordinate == MINUS_ONE
    {
        return Err(Ed448Error::InvalidPublicKey);
    }
    Ok(())
}
