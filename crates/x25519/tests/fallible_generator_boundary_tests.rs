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
    let generate: Generation = crypto_x25519::generate_x25519_keypair;
    let (public, secret) = generate().expect("configured OS entropy");
    assert!(!public.is_empty());
    assert!(!secret.is_empty());
    let (peer_public, peer_secret) = crypto_x25519::generate_x25519_keypair_from_seed(&[7u8; 32]);
    let shared =
        crypto_x25519::derive_x25519_shared_secret(&secret, &peer_public).expect("agreement");
    let peer_shared =
        crypto_x25519::derive_x25519_shared_secret(&peer_secret, &public).expect("peer agreement");
    assert_eq!(shared, peer_shared);
}
