// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Single executable operation-response boundary for the WASM package.
//!
//! Operation-specific SDK helpers remain separate from this adapter. Both
//! generated protobuf and generated ProtoJSON requests return a binary
//! `CryptoOperationResponse`, preventing WASM from creating a parallel error or
//! dispatch contract.

use crypto_runtime::operation_contract::{
    process_operation_response as process_operation_response_request,
    process_operation_response_json as process_operation_response_json_request,
};
use crypto_runtime::operation_contract::{
    MAX_CRYPTO_PROTO_JSON_BYTES, MAX_CRYPTO_PROTO_MESSAGE_BYTES,
};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

#[wasm_bindgen(js_name = processOperationResponse)]
/// Execute one generated binary protobuf request and return a binary `CryptoOperationResponse`.
#[must_use]
pub fn process_operation_response(request: &Uint8Array) -> Uint8Array {
    let request = bounded_request(request, MAX_CRYPTO_PROTO_MESSAGE_BYTES);
    let output: Zeroizing<Vec<u8>> = process_operation_response_request(request.as_slice());
    Uint8Array::from(output.as_slice())
}

#[wasm_bindgen(js_name = processOperationResponseJson)]
/// Execute one generated ProtoJSON request and return a binary `CryptoOperationResponse`.
#[must_use]
pub fn process_operation_response_json(request_json: &Uint8Array) -> Uint8Array {
    let request_json = bounded_request(request_json, MAX_CRYPTO_PROTO_JSON_BYTES);
    let output: Zeroizing<Vec<u8>> =
        process_operation_response_json_request(request_json.as_slice());
    Uint8Array::from(output.as_slice())
}

fn bounded_request(request: &Uint8Array, maximum: usize) -> Zeroizing<Vec<u8>> {
    let request_len = match usize::try_from(request.length()) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    };
    if request_len <= maximum {
        return Zeroizing::new(request.to_vec());
    }

    // Pass a bounded sentinel through the shared Rust decoder so oversized
    // input receives the same structured resource-limit envelope as native
    // callers without first copying an attacker-sized JS buffer into WASM.
    let Some(sentinel_len) = maximum.checked_add(1) else {
        return Zeroizing::new(Vec::new());
    };
    Zeroizing::new(vec![0_u8; sentinel_len])
}
