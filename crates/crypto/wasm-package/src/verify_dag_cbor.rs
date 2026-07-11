// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use codec_cbor::{compute_cid_dag_cbor, verify_dag_cbor_cid};
use js_sys::{Object, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::write_js_object::{set_bool, set_string};

#[wasm_bindgen(js_name = dagCborComputeCid)]
/// Compute a CIDv1 dag-cbor/sha2-256 string for already-canonical DAG-CBOR bytes.
pub fn dag_cbor_compute_cid(bytes: &Uint8Array) -> String {
    compute_cid_dag_cbor(&bytes.to_vec())
}

#[wasm_bindgen(js_name = dagCborVerifyCid)]
/// Recompute and compare a CIDv1 dag-cbor/sha2-256 string.
pub fn dag_cbor_verify_cid(cid: &str, bytes: &Uint8Array) -> Result<JsValue, JsValue> {
    let (valid, expected_cid, actual_cid) = verify_dag_cbor_cid(cid, &bytes.to_vec());
    let object = Object::new();
    set_bool(&object, "valid", valid)?;
    set_string(&object, "expectedCid", &expected_cid)?;
    set_string(&object, "actualCid", &actual_cid)?;
    Ok(object.into())
}
