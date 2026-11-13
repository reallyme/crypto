// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(any(feature = "native", feature = "wasm"))]
#![allow(missing_docs)]

use crypto_core::CryptoError;
use zeroize::Zeroizing;

// Keep the public function's canonical fallible type visible to both test lanes.
type Generation = fn() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError>;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[allow(deprecated, clippy::expect_used)]
fn compatibility_generator_keeps_name_and_returns_the_canonical_result() {
    let generate: Generation = crypto_secp256k1::generate_secp256k1_keypair;
    let (public, secret) = generate().expect("configured OS entropy");
    assert!(!public.is_empty());
    assert!(!secret.is_empty());
    let signature =
        crypto_secp256k1::sign_secp256k1(&secret, b"typed entropy boundary").expect("signature");
    crypto_secp256k1::verify_secp256k1(&signature, b"typed entropy boundary", &public)
        .expect("verification");
}
