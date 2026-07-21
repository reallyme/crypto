// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, Zeroizing};

use crate::map_error::{map_crypto_error, provider_failure};
use crate::validate_bytes::{copy_bounded, copy_exact, MAX_WASM_INPUT_LENGTH};

const SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN: usize = 32;
const SLH_DSA_SHA2_128S_SECRET_KEY_LEN: usize = 64;
const SLH_DSA_SHA2_128S_SIGNATURE_LEN: usize = 7_856;
const SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN: usize = 16;

fn set_bytes(object: &Object, name: &str, bytes: &[u8]) -> Result<(), JsValue> {
    Reflect::set(object, &JsValue::from_str(name), &Uint8Array::from(bytes))
        .map_err(|_| provider_failure())?;
    Ok(())
}

fn keypair_to_js(
    public_key: Vec<u8>,
    mut secret_key: Zeroizing<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN
        || secret_key.len() != SLH_DSA_SHA2_128S_SECRET_KEY_LEN
    {
        return Err(provider_failure());
    }
    let object = Object::new();
    set_bytes(&object, "publicKey", &public_key)?;
    set_bytes(&object, "secretKey", &secret_key)?;
    secret_key.zeroize();
    Ok(object.into())
}

#[wasm_bindgen(js_name = slhDsaSha2128sGenerateKeypair)]
/// Generate an SLH-DSA-SHA2-128s keypair.
pub fn slh_dsa_sha2_128s_generate_keypair() -> Result<JsValue, JsValue> {
    let (public_key, secret_key) =
        crypto_runtime::slh_dsa::generate_slh_dsa_sha2_128s_keypair().map_err(map_crypto_error)?;
    keypair_to_js(public_key, secret_key)
}

#[wasm_bindgen(js_name = slhDsaSha2128sDeriveKeypair)]
/// Derive an SLH-DSA-SHA2-128s keypair from the three FIPS 205 seeds.
pub fn slh_dsa_sha2_128s_derive_keypair(
    sk_seed: &Uint8Array,
    sk_prf: &Uint8Array,
    pk_seed: &Uint8Array,
) -> Result<JsValue, JsValue> {
    let sk_seed = Zeroizing::new(copy_exact(sk_seed, SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN)?);
    let sk_prf = Zeroizing::new(copy_exact(sk_prf, SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN)?);
    let pk_seed = Zeroizing::new(copy_exact(pk_seed, SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN)?);
    let (public_key, secret_key) =
        crypto_runtime::slh_dsa::derive_slh_dsa_sha2_128s_keypair(&sk_seed, &sk_prf, &pk_seed)
            .map_err(map_crypto_error)?;
    keypair_to_js(public_key, secret_key)
}

#[wasm_bindgen(js_name = slhDsaSha2128sSign)]
/// Sign a message with SLH-DSA-SHA2-128s.
pub fn slh_dsa_sha2_128s_sign(
    secret_key: &Uint8Array,
    message: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let secret_key = Zeroizing::new(copy_exact(secret_key, SLH_DSA_SHA2_128S_SECRET_KEY_LEN)?);
    let message = Zeroizing::new(copy_bounded(message, MAX_WASM_INPUT_LENGTH)?);
    let signature = crypto_runtime::slh_dsa::sign_slh_dsa_sha2_128s(&secret_key, &message)
        .map_err(map_crypto_error)?;
    if signature.len() != SLH_DSA_SHA2_128S_SIGNATURE_LEN {
        return Err(provider_failure());
    }
    Ok(Uint8Array::from(signature.as_slice()))
}

#[wasm_bindgen(js_name = slhDsaSha2128sVerify)]
/// Verify an SLH-DSA-SHA2-128s detached signature.
pub fn slh_dsa_sha2_128s_verify(
    public_key: &Uint8Array,
    message: &Uint8Array,
    signature: &Uint8Array,
) -> Result<(), JsValue> {
    let public_key = copy_exact(public_key, SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN)?;
    let signature = copy_exact(signature, SLH_DSA_SHA2_128S_SIGNATURE_LEN)?;
    let message = Zeroizing::new(copy_bounded(message, MAX_WASM_INPUT_LENGTH)?);
    crypto_runtime::slh_dsa::verify_slh_dsa_sha2_128s(&public_key, &message, &signature)
        .map_err(map_crypto_error)
}
