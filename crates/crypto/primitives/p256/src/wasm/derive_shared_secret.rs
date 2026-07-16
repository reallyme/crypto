// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KeyAgreementFailureKind};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const P256_SECRET_KEY_LEN: usize = 32;
const P256_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
const P256_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 65;
const P256_SHARED_SECRET_LEN: usize = 32;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = deriveP256SharedSecret)]
    fn js_derive_p256_shared_secret(secret_key: Uint8Array, public_key: Uint8Array) -> Uint8Array;
}

/// Derive the raw P-256 ECDH shared secret with the browser backend.
pub fn derive_p256_shared_secret(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if secret_key.len() != P256_SECRET_KEY_LEN
        || (public_key.len() != P256_PUBLIC_KEY_COMPRESSED_LEN
            && public_key.len() != P256_PUBLIC_KEY_UNCOMPRESSED_LEN)
    {
        return Err(CryptoError::InvalidKey);
    }

    let secret = Uint8Array::from(secret_key);
    let public = Uint8Array::from(public_key);
    let shared = Zeroizing::new(js_derive_p256_shared_secret(secret, public).to_vec());
    if shared.len() != P256_SHARED_SECRET_LEN || shared.iter().all(|byte| *byte == 0) {
        return Err(CryptoError::KeyAgreementFailure {
            kind: KeyAgreementFailureKind::DeriveSharedSecretFailed,
        });
    }

    Ok(shared)
}
