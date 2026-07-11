// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    // function decompressSecp256k1PublicKey(pub: Uint8Array): { x: Uint8Array, y: Uint8Array }
    #[wasm_bindgen(js_name = decompressSecp256k1PublicKey)]
    fn js_decompress_secp256k1_public_key(pubkey: Uint8Array) -> JsValue;
}

/// Validates this crate's canonical compressed SEC1 secp256k1 public key shape.
///
/// The lightweight encode/decode helpers only accept the 33-byte compressed
/// SEC1 form (`0x02` or `0x03` plus x-coordinate). They intentionally do not
/// parse the point; callers that need full curve validation should call
/// [`decompress_secp256k1_public_key`] or a signing/verification operation.
pub fn assert_secp256k1_public_key(pubkey: &[u8]) -> Result<&[u8], CryptoError> {
    if pubkey.len() != 33 {
        return Err(CryptoError::InvalidKey);
    }
    match pubkey[0] {
        0x02 | 0x03 => Ok(pubkey),
        _ => Err(CryptoError::InvalidKey),
    }
}

/// Returns the canonical compressed SEC1 public-key bytes after shape validation.
pub fn encode_secp256k1_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_secp256k1_public_key(pubkey)?.to_vec())
}

/// Decodes the canonical public-key representation.
///
/// secp256k1 uses the same 33-byte compressed SEC1 bytes at the API and wire
/// boundary, so decoding is a validating copy rather than a re-serialization.
pub fn decode_secp256k1_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_secp256k1_public_key(pubkey)?.to_vec())
}

/// Decompresses a compressed SEC1 secp256k1 public key.
///
/// The JavaScript backend is responsible for parsing the point and rejecting
/// invalid curve encodings before returning affine coordinates.
/// Returns (x[32], y[32]).
pub fn decompress_secp256k1_public_key(
    pubkey_compressed: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    assert_secp256k1_public_key(pubkey_compressed)?;

    let v = js_decompress_secp256k1_public_key(Uint8Array::from(pubkey_compressed));
    let obj = Object::from(v);

    let x = Reflect::get(&obj, &JsValue::from_str("x")).map_err(|_| CryptoError::InvalidKey)?;
    let y = Reflect::get(&obj, &JsValue::from_str("y")).map_err(|_| CryptoError::InvalidKey)?;

    let x = Uint8Array::new(&x).to_vec();
    let y = Uint8Array::new(&y).to_vec();

    if x.len() != 32 || y.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    Ok((x, y))
}
