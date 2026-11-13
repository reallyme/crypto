// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ReallyMe's intentionally ratified AKP JWK encodings for PQ public keys.

use crate::canonicalize_jwk::canonicalize_jwk;
use crate::{AkpJwk, JwkOptions, JwtError};
use codec_base64url::bytes_to_base64url;

fn pq_public_key_to_jwk(
    public_key: &[u8],
    expected_length: usize,
    alg: &'static str,
    key_use: &'static str,
    invalid_error: JwtError,
    options: JwkOptions,
) -> Result<AkpJwk, JwtError> {
    if public_key.len() != expected_length {
        return Err(invalid_error);
    }

    Ok(AkpJwk {
        kty: "AKP".to_owned(),
        alg: alg.to_owned(),
        public_key: bytes_to_base64url(public_key),
        use_: ((key_use == "sig" && options.use_sig) || (key_use == "enc" && options.use_enc))
            .then(|| key_use.to_owned()),
        kid: options.kid,
    })
}

fn pq_public_key_to_jwk_jcs(jwk: &AkpJwk) -> Result<String, JwtError> {
    canonicalize_jwk(jwk)
}

macro_rules! define_pq_jwk {
    ($to_jwk:ident, $to_jcs:ident, $length:expr, $curve:literal, $use:literal, $error:expr) => {
        #[doc = concat!("Converts a raw ", $curve, " public key to ReallyMe's AKP JWK.")]
        pub fn $to_jwk(public_key: &[u8], options: JwkOptions) -> Result<AkpJwk, JwtError> {
            pq_public_key_to_jwk(public_key, $length, $curve, $use, $error, options)
        }

        #[doc = concat!("Converts a raw ", $curve, " public key to its JCS-canonical JWK.")]
        pub fn $to_jcs(public_key: &[u8], options: JwkOptions) -> Result<String, JwtError> {
            let jwk = $to_jwk(public_key, options)?;
            pq_public_key_to_jwk_jcs(&jwk)
        }
    };
}

define_pq_jwk!(
    mldsa44_public_key_to_jwk,
    mldsa44_public_key_to_jwk_jcs,
    1312,
    "ML-DSA-44",
    "sig",
    JwtError::PRIMITIVE_INVALID_PUBLIC_KEY
);
define_pq_jwk!(
    mldsa65_public_key_to_jwk,
    mldsa65_public_key_to_jwk_jcs,
    1952,
    "ML-DSA-65",
    "sig",
    JwtError::PRIMITIVE_INVALID_PUBLIC_KEY
);
define_pq_jwk!(
    mlkem512_public_key_to_jwk,
    mlkem512_public_key_to_jwk_jcs,
    800,
    "ML-KEM-512",
    "enc",
    JwtError::PRIMITIVE_INVALID_PUBLIC_KEY
);
define_pq_jwk!(
    mlkem768_public_key_to_jwk,
    mlkem768_public_key_to_jwk_jcs,
    1184,
    "ML-KEM-768",
    "enc",
    JwtError::PRIMITIVE_INVALID_PUBLIC_KEY
);
define_pq_jwk!(
    slh_dsa_sha2_128s_public_key_to_jwk,
    slh_dsa_sha2_128s_public_key_to_jwk_jcs,
    32,
    "SLH-DSA-SHA2-128s",
    "sig",
    JwtError::PRIMITIVE_INVALID_PUBLIC_KEY
);
define_pq_jwk!(
    x_wing_768_public_key_to_jwk,
    x_wing_768_public_key_to_jwk_jcs,
    1216,
    "X-Wing-768",
    "enc",
    JwtError::PRIMITIVE_INVALID_PUBLIC_KEY
);
