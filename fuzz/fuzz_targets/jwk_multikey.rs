// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz public JWK and multikey parsers reached from untrusted application
//! input. Property: malformed JSON, unknown algorithms, invalid base encodings,
//! and malformed multikey strings must fail closed without panicking.

#![no_main]

use envelopes_jwk::{Jwk, JwkOptions, Jwks};
use envelopes_jwk_multikey::{jwk_to_multikey, multikey_to_jwk};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = core::str::from_utf8(data) else {
        return;
    };

    if let Ok(jwk) = serde_json::from_str::<Jwk>(input) {
        let _ = jwk.public_key_bytes();
        let _ = jwk_to_multikey(&jwk);
    }

    if let Ok(jwks) = serde_json::from_str::<Jwks>(input) {
        for jwk in jwks.into_keys() {
            let _ = jwk.public_key_bytes();
            let _ = jwk_to_multikey(&jwk);
        }
    }

    let _ = multikey_to_jwk(input, JwkOptions::default());
});
