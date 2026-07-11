// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use codec_multibase::{bytes_to_multibase58btc, bytes_to_multibase_base64url, multibase_to_bytes};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::map_error::invalid_input;

#[wasm_bindgen(js_name = multibaseBase64urlEncode)]
/// Encode bytes with the multibase base64url prefix.
pub fn multibase_base64url_encode(bytes: &Uint8Array) -> String {
    bytes_to_multibase_base64url(&bytes.to_vec())
}

#[wasm_bindgen(js_name = multibaseBase58btcEncode)]
/// Encode bytes with the multibase base58btc prefix.
pub fn multibase_base58btc_encode(bytes: &Uint8Array) -> String {
    bytes_to_multibase58btc(&bytes.to_vec())
}

#[wasm_bindgen(js_name = multibaseDecode)]
/// Decode a supported multibase string.
pub fn multibase_decode(encoded: &str) -> Result<Uint8Array, JsValue> {
    let decoded = multibase_to_bytes(encoded).map_err(|_| invalid_input())?;
    Ok(Uint8Array::from(decoded.as_slice()))
}
