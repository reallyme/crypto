// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use codec_base64url::{base64url_to_bytes, bytes_to_base64url};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::map_error::invalid_input;

#[wasm_bindgen(js_name = base64urlEncode)]
/// Encode bytes as RFC 4648 URL-safe base64 without padding.
pub fn base64url_encode(bytes: &Uint8Array) -> String {
    bytes_to_base64url(&bytes.to_vec())
}

#[wasm_bindgen(js_name = base64urlDecode)]
/// Decode strict, unpadded RFC 4648 URL-safe base64.
pub fn base64url_decode(encoded: &str) -> Result<Uint8Array, JsValue> {
    let decoded = base64url_to_bytes(encoded).map_err(|_| invalid_input())?;
    Ok(Uint8Array::from(decoded.as_slice()))
}
