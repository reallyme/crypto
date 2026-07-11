// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = deriveX25519SharedSecret)]
    fn js_derive_x25519_shared_secret(secret_key: Uint8Array, public_key: Uint8Array)
        -> Uint8Array;
}

/// Derive an X25519 shared secret.
/// shared_secret = X25519(secret_key, public_key)
pub fn derive_x25519_shared_secret(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if secret_key.len() != 32 || public_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let sk = Uint8Array::from(secret_key);
    let pk = Uint8Array::from(public_key);

    let out = Zeroizing::new(js_derive_x25519_shared_secret(sk, pk).to_vec());

    if out.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    Ok(out)
}
