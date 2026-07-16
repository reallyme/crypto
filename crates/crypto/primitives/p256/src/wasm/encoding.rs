// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = compressP256PublicKey)]
    fn js_compress_p256_public_key(pub_uncompressed: Uint8Array) -> Uint8Array;

    #[wasm_bindgen(js_name = decompressP256PublicKey)]
    fn js_decompress_p256_public_key(pub_compressed: Uint8Array) -> Uint8Array;
}

/// Compresses a 65-byte SEC1 P-256 public key through the JavaScript provider.
pub fn compress_p256(pubkey_uncompressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if pubkey_uncompressed.len() != 65 {
        return Err(CryptoError::InvalidKey);
    }

    let pk = Uint8Array::from(pubkey_uncompressed);
    let out = js_compress_p256_public_key(pk).to_vec();

    if out.len() != 33 {
        return Err(CryptoError::InvalidKey);
    }

    Ok(out)
}

/// Decompresses a 33-byte SEC1 P-256 public key through the JavaScript provider.
pub fn decompress_p256(pubkey_compressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if pubkey_compressed.len() != 33 {
        return Err(CryptoError::InvalidKey);
    }

    let pk = Uint8Array::from(pubkey_compressed);
    let out = js_decompress_p256_public_key(pk).to_vec();

    if out.len() != 65 {
        return Err(CryptoError::InvalidKey);
    }

    Ok(out)
}
