// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use codec_multikey::encode_multikey;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use envelopes_jwk::JwkOptions;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use envelopes_jwk_multikey::{jwk_to_multikey, multikey_to_jwk};

#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
#[test]
fn secp256k1_multikey_jwk_roundtrip() {
    // Deterministic compressed secp256k1 public key
    let mut compressed = vec![0x02]; // even Y
    compressed.extend([7u8; 32]); // X coordinate

    // Canonical multikey
    let multikey = encode_multikey("secp256k1-pub", &compressed).expect("encode multikey");

    let jwk = multikey_to_jwk(&multikey, JwkOptions::default()).expect("multikey → jwk");

    let out = jwk_to_multikey(&jwk).expect("jwk → multikey");

    assert_eq!(multikey, out);
}
