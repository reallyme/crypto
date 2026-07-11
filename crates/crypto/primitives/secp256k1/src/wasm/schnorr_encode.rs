// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{BIP340_SCHNORR_PUBLIC_KEY_LEN, SECP256K1_SECRET_KEY_LEN};
use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = deriveBip340SchnorrPublicKey)]
    fn js_derive_bip340_schnorr_public_key(secret_key: Uint8Array) -> Uint8Array;
}

/// Derive the BIP-340 x-only public key for a secp256k1 secret scalar.
pub fn derive_bip340_schnorr_public_key(secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != SECP256K1_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    let public_key = js_derive_bip340_schnorr_public_key(Uint8Array::from(secret_key)).to_vec();
    if public_key.len() != BIP340_SCHNORR_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    Ok(public_key)
}

/// Encode a BIP-340 x-only public key after validating its length.
pub fn encode_bip340_schnorr_public_key(public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if public_key.len() != BIP340_SCHNORR_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    Ok(public_key.to_vec())
}

/// Decode a BIP-340 x-only public key after validating its length.
pub fn decode_bip340_schnorr_public_key(public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode_bip340_schnorr_public_key(public_key)
}
