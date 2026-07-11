// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN, SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN,
    SLH_DSA_SHA2_128S_SECRET_KEY_LEN,
};
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = generateSlhDsaSha2128sKeypair)]
    fn js_generate_slh_dsa_sha2_128s_keypair() -> JsValue;

    #[wasm_bindgen(js_name = deriveSlhDsaSha2128sKeypair)]
    fn js_derive_slh_dsa_sha2_128s_keypair(
        sk_seed: Uint8Array,
        sk_prf: Uint8Array,
        pk_seed: Uint8Array,
    ) -> JsValue;
}

fn key_generation_failed() -> CryptoError {
    CryptoError::Signature {
        backend: SignatureBackend::Wasm,
        operation: SignatureOperation::KeyManagement,
        kind: SignatureFailureKind::KeyGenerationFailed,
    }
}

fn read_keypair(value: JsValue) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let object = Object::from(value);
    let public = Reflect::get(&object, &JsValue::from_str("publicKey"))
        .map_err(|_| key_generation_failed())?;
    let secret = Reflect::get(&object, &JsValue::from_str("secretKey"))
        .map_err(|_| key_generation_failed())?;
    let public_key = Uint8Array::new(&public).to_vec();
    let secret_key = Zeroizing::new(Uint8Array::new(&secret).to_vec());

    if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN
        || secret_key.len() != SLH_DSA_SHA2_128S_SECRET_KEY_LEN
    {
        return Err(key_generation_failed());
    }

    Ok((public_key, secret_key))
}

/// Generate an SLH-DSA-SHA2-128s keypair through the wasm host provider.
pub fn generate_slh_dsa_sha2_128s_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    read_keypair(js_generate_slh_dsa_sha2_128s_keypair())
}

/// Derive an SLH-DSA-SHA2-128s keypair from the three FIPS 205 keygen seeds.
pub fn derive_slh_dsa_sha2_128s_keypair(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    if sk_seed.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
        || sk_prf.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
        || pk_seed.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
    {
        return Err(CryptoError::InvalidKey);
    }

    read_keypair(js_derive_slh_dsa_sha2_128s_keypair(
        Uint8Array::from(sk_seed),
        Uint8Array::from(sk_prf),
        Uint8Array::from(pk_seed),
    ))
}
