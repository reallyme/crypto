// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use js_sys::Uint8Array;
use wasm_bindgen::JsValue;

use crate::map_error::invalid_input;

/// Largest variable-length byte input accepted by a direct WASM primitive.
///
/// The structured operation boundary uses the same one-mebibyte ceiling. Raw
/// primitive exports enforce it before calling `Uint8Array::to_vec`, so an
/// untrusted JavaScript caller cannot force an unbounded Rust allocation.
pub(crate) const MAX_WASM_INPUT_LENGTH: usize = 1_048_576;
/// Largest authenticated ciphertext accepted by direct AEAD/HPKE exports.
///
/// Every currently exposed encrypting construction appends a 16-byte tag.
pub(crate) const MAX_WASM_CIPHERTEXT_LENGTH: usize = 1_048_592;

pub(crate) fn copy_exact(input: &Uint8Array, expected_len: usize) -> Result<Vec<u8>, JsValue> {
    let input_len = usize::try_from(input.length()).map_err(|_| invalid_input())?;
    if input_len != expected_len {
        return Err(invalid_input());
    }
    Ok(input.to_vec())
}

pub(crate) fn copy_bounded(input: &Uint8Array, maximum_len: usize) -> Result<Vec<u8>, JsValue> {
    let input_len = usize::try_from(input.length()).map_err(|_| invalid_input())?;
    if input_len > maximum_len {
        return Err(invalid_input());
    }
    Ok(input.to_vec())
}

pub(crate) fn copy_bounded_nonempty(
    input: &Uint8Array,
    maximum_len: usize,
) -> Result<Vec<u8>, JsValue> {
    let bytes = copy_bounded(input, maximum_len)?;
    if bytes.is_empty() {
        return Err(invalid_input());
    }
    Ok(bytes)
}
