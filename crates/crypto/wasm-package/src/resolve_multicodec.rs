// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use codec_multicodec::{lookup_codec_prefix, CodecSpec, MULTICODEC_TABLE};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::map_error::unsupported_algorithm;
use crate::write_js_object::{codec_lookup_to_js, codec_spec_to_js};

fn find_codec_spec(codec_name: &str) -> Option<(&'static str, &'static CodecSpec)> {
    MULTICODEC_TABLE
        .iter()
        .find(|(name, _)| *name == codec_name)
        .map(|(name, spec)| (*name, spec))
}

#[wasm_bindgen(js_name = multicodecPrefixForName)]
/// Return multicodec metadata for a canonical codec name.
pub fn multicodec_prefix_for_name(codec_name: &str) -> Result<JsValue, JsValue> {
    let (name, spec) = find_codec_spec(codec_name).ok_or_else(unsupported_algorithm)?;
    codec_spec_to_js(name, spec)
}

#[wasm_bindgen(js_name = multicodecLookupPrefix)]
/// Resolve a byte slice that starts with a known multicodec prefix.
pub fn multicodec_lookup_prefix(bytes: &Uint8Array) -> Result<JsValue, JsValue> {
    let bytes = bytes.to_vec();
    let found = lookup_codec_prefix(&bytes).ok_or_else(unsupported_algorithm)?;
    codec_lookup_to_js(found)
}
