// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    BIP340_SCHNORR_AUX_RAND_LEN, BIP340_SCHNORR_MESSAGE_LEN, BIP340_SCHNORR_SIGNATURE_LEN,
    SECP256K1_SECRET_KEY_LEN,
};
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroize;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = signBip340Schnorr)]
    fn js_sign_bip340_schnorr(
        message32: Uint8Array,
        secret_key: Uint8Array,
        aux_rand32: Uint8Array,
    ) -> Uint8Array;
}

/// Sign a 32-byte BIP-340 message with explicit 32-byte auxiliary randomness.
pub fn sign_bip340_schnorr(
    secret_key: &[u8],
    message32: &[u8],
    aux_rand32: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != SECP256K1_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    if message32.len() != BIP340_SCHNORR_MESSAGE_LEN
        || aux_rand32.len() != BIP340_SCHNORR_AUX_RAND_LEN
    {
        return Err(CryptoError::Signature {
            backend: SignatureBackend::Wasm,
            operation: SignatureOperation::Sign,
            kind: SignatureFailureKind::InvalidMessage,
        });
    }

    let mut signature = js_sign_bip340_schnorr(
        Uint8Array::from(message32),
        Uint8Array::from(secret_key),
        Uint8Array::from(aux_rand32),
    )
    .to_vec();

    if signature.len() != BIP340_SCHNORR_SIGNATURE_LEN {
        signature.zeroize();
        return Err(CryptoError::Signature {
            backend: SignatureBackend::Wasm,
            operation: SignatureOperation::Sign,
            kind: SignatureFailureKind::InvalidSignature,
        });
    }

    Ok(signature)
}
