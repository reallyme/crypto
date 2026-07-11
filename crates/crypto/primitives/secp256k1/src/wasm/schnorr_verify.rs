// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    BIP340_SCHNORR_MESSAGE_LEN, BIP340_SCHNORR_PUBLIC_KEY_LEN, BIP340_SCHNORR_SIGNATURE_LEN,
};
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = verifyBip340Schnorr)]
    fn js_verify_bip340_schnorr(
        signature: Uint8Array,
        message32: Uint8Array,
        public_key_xonly: Uint8Array,
    ) -> bool;
}

/// Verify a BIP-340 Schnorr signature over a 32-byte message.
pub fn verify_bip340_schnorr(
    signature: &[u8],
    message32: &[u8],
    public_key_xonly: &[u8],
) -> Result<(), CryptoError> {
    if signature.len() != BIP340_SCHNORR_SIGNATURE_LEN {
        return Err(CryptoError::Signature {
            backend: SignatureBackend::Wasm,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        });
    }
    if message32.len() != BIP340_SCHNORR_MESSAGE_LEN {
        return Err(CryptoError::Signature {
            backend: SignatureBackend::Wasm,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidMessage,
        });
    }
    if public_key_xonly.len() != BIP340_SCHNORR_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    if js_verify_bip340_schnorr(
        Uint8Array::from(signature),
        Uint8Array::from(message32),
        Uint8Array::from(public_key_xonly),
    ) {
        Ok(())
    } else {
        Err(CryptoError::Signature {
            backend: SignatureBackend::Wasm,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    }
}
