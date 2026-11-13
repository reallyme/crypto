// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Publish byte results only after the JavaScript property write succeeds.

use crypto_core::CryptoError;
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::JsValue;

use crate::map_error::map_crypto_error;

pub(crate) fn set_bytes(object: &Object, name: &str, bytes: &[u8]) -> Result<(), JsValue> {
    let output = Uint8Array::from(bytes);
    let stored = Reflect::set(object, &JsValue::from_str(name), &output)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)
        .and_then(require_stored);
    if let Err(error) = stored {
        // A rejected write must not leave an unpublished copy of private output
        // waiting for JavaScript garbage collection. The Rust source keeps its
        // existing clearing owner throughout this boundary.
        let _cleared = output.fill(0, 0, output.length());
        return Err(map_crypto_error(error));
    }
    Ok(())
}

fn require_stored(stored: bool) -> Result<(), CryptoError> {
    if stored {
        Ok(())
    } else {
        Err(CryptoError::BACKEND_INTERNAL)
    }
}

#[cfg(test)]
#[path = "set_bytes_tests.rs"]
mod tests;
