// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use codec_multicodec::VARIABLE_KEY_LENGTH;
use codec_multikey::{encode_multikey, parse_multikey};
use js_sys::{Object, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::map_error::invalid_input;
use crate::write_js_object::{set_bytes, set_string, set_u32};

#[wasm_bindgen(js_name = multikeyEncode)]
/// Encode a public key as a multibase base58btc multikey.
pub fn multikey_encode(codec_name: &str, public_key: &Uint8Array) -> Result<String, JsValue> {
    encode_multikey(codec_name, &public_key.to_vec()).map_err(|_| invalid_input())
}

#[wasm_bindgen(js_name = multikeyParse)]
/// Parse and validate a multikey string.
pub fn multikey_parse(multikey: &str) -> Result<JsValue, JsValue> {
    let parsed = parse_multikey(multikey).map_err(|_| invalid_input())?;
    let object = Object::new();
    set_string(&object, "codecName", parsed.codec_name)?;
    set_string(&object, "algorithmName", parsed.alg)?;
    set_bytes(&object, "publicKey", &parsed.public_key)?;
    if parsed.key_length != VARIABLE_KEY_LENGTH {
        set_u32(&object, "expectedPublicKeyLength", parsed.key_length)?;
    }
    Ok(object.into())
}
