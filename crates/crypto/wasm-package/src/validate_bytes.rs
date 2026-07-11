// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use js_sys::Uint8Array;
use wasm_bindgen::JsValue;

use crate::map_error::invalid_input;

pub(crate) fn copy_exact(input: &Uint8Array, expected_len: usize) -> Result<Vec<u8>, JsValue> {
    let input_len = usize::try_from(input.length()).map_err(|_| invalid_input())?;
    if input_len != expected_len {
        return Err(invalid_input());
    }
    Ok(input.to_vec())
}
