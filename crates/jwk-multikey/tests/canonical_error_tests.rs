// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

use crypto_core::CryptoError;
use envelopes_jwk::{JwkOptions, JwtError};
use envelopes_jwk_multikey::{multikey_to_jwk, JwkMultikeyError};

#[test]
fn envelope_adapter_error_names_share_the_canonical_type() {
    let source: JwtError = CryptoError::BACKEND_INTERNAL;
    let adapter: JwkMultikeyError = source;
    assert_eq!(adapter, CryptoError::BACKEND_INTERNAL);
}

#[test]
fn invalid_public_key_is_not_an_internal_encoding_failure() {
    // The codec checks the byte envelope; the JWK layer rejects this small-order
    // Ed25519 identity. Preserve that originating canonical key rejection.
    let encoded =
        codec_multikey::encode_multikey("ed25519-pub", &[0_u8; 32]).expect("public envelope");
    assert_eq!(
        multikey_to_jwk(&encoded, JwkOptions::default()).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    );
}

#[test]
fn malformed_multibase_remains_an_input_encoding_rejection() {
    assert_eq!(
        multikey_to_jwk("zInvalidKey", JwkOptions::default()).err(),
        Some(CryptoError::PRIMITIVE_INVALID_ENCODING)
    );
}
