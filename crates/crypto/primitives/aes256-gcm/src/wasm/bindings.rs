// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_name = aes256GcmEncrypt)]
    pub(super) fn js_aes256_gcm_encrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        aad: Uint8Array,
        plaintext: Uint8Array,
    ) -> Result<Uint8Array, JsValue>;

    #[wasm_bindgen(catch, js_name = aes256GcmDecrypt)]
    pub(super) fn js_aes256_gcm_decrypt(
        key: Uint8Array,
        nonce: Uint8Array,
        aad: Uint8Array,
        ciphertext: Uint8Array,
    ) -> Result<Uint8Array, JsValue>;
}
