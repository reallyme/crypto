// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_rsa::{
    verify_rsa_pkcs1v15, verify_rsa_pss, RsaHash, RsaPssParams, RsaPublicKeyDerEncoding,
};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::map_error::{invalid_input, map_crypto_error};

fn parse_encoding(value: u32) -> Result<RsaPublicKeyDerEncoding, JsValue> {
    RsaPublicKeyDerEncoding::from_ffi_id(value).ok_or_else(invalid_input)
}

fn parse_hash(value: u32) -> Result<RsaHash, JsValue> {
    RsaHash::from_ffi_id(value).ok_or_else(invalid_input)
}

#[wasm_bindgen(js_name = rsaVerifyPkcs1v15)]
/// Verify an RSASSA-PKCS1-v1_5 signature against a DER RSA public key.
pub fn rsa_verify_pkcs1v15(
    public_key_der: &Uint8Array,
    public_key_encoding: u32,
    hash_suite: u32,
    message: &Uint8Array,
    signature: &Uint8Array,
) -> Result<(), JsValue> {
    let encoding = parse_encoding(public_key_encoding)?;
    let hash = parse_hash(hash_suite)?;
    verify_rsa_pkcs1v15(
        &public_key_der.to_vec(),
        encoding,
        hash,
        &message.to_vec(),
        &signature.to_vec(),
    )
    .map_err(map_crypto_error)
}

#[wasm_bindgen(js_name = rsaVerifyPss)]
/// Verify an RSASSA-PSS signature against a DER RSA public key.
pub fn rsa_verify_pss(
    public_key_der: &Uint8Array,
    public_key_encoding: u32,
    message_hash_suite: u32,
    mgf1_hash_suite: u32,
    salt_len: u32,
    message: &Uint8Array,
    signature: &Uint8Array,
) -> Result<(), JsValue> {
    let encoding = parse_encoding(public_key_encoding)?;
    let message_hash = parse_hash(message_hash_suite)?;
    let mgf1_hash = parse_hash(mgf1_hash_suite)?;
    let salt_len = usize::try_from(salt_len).map_err(|_| invalid_input())?;
    verify_rsa_pss(
        &public_key_der.to_vec(),
        encoding,
        RsaPssParams {
            message_hash,
            mgf1_hash,
            salt_len,
        },
        &message.to_vec(),
        &signature.to_vec(),
    )
    .map_err(map_crypto_error)
}
