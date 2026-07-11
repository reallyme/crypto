// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, SignatureFailureKind, SignatureOperation};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, Zeroizing};

use crate::map_error::{invalid_input, invalid_signature, provider_failure};

const SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN: usize = 32;
const SLH_DSA_SHA2_128S_SECRET_KEY_LEN: usize = 64;
const SLH_DSA_SHA2_128S_SIGNATURE_LEN: usize = 7_856;
const SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN: usize = 16;

fn map_slh_dsa_error(error: CryptoError) -> JsValue {
    match error {
        CryptoError::InvalidKey => invalid_input(),
        CryptoError::Signature {
            operation:
                SignatureOperation::Sign
                | SignatureOperation::Verify
                | SignatureOperation::KeyManagement,
            kind: SignatureFailureKind::InvalidPrivateKey | SignatureFailureKind::InvalidPublicKey,
            ..
        } => invalid_input(),
        CryptoError::Signature {
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature | SignatureFailureKind::InvalidMessage,
            ..
        } => invalid_signature(),
        CryptoError::Signature {
            kind: SignatureFailureKind::KeyGenerationFailed | SignatureFailureKind::BackendFailure,
            ..
        } => provider_failure(),
        _ => provider_failure(),
    }
}

fn require_len(bytes: &Uint8Array, expected_len: usize) -> Result<Vec<u8>, JsValue> {
    let bytes = bytes.to_vec();
    if bytes.len() == expected_len {
        Ok(bytes)
    } else {
        Err(invalid_input())
    }
}

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
        crypto_slh_dsa::generate_slh_dsa_sha2_128s_keypair().map_err(map_slh_dsa_error)?;
    keypair_to_js(public_key, secret_key)
}

#[wasm_bindgen(js_name = slhDsaSha2128sDeriveKeypair)]
/// Derive an SLH-DSA-SHA2-128s keypair from the three FIPS 205 seeds.
pub fn slh_dsa_sha2_128s_derive_keypair(
    sk_seed: &Uint8Array,
    sk_prf: &Uint8Array,
    pk_seed: &Uint8Array,
) -> Result<JsValue, JsValue> {
    let sk_seed = Zeroizing::new(require_len(sk_seed, SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN)?);
    let sk_prf = Zeroizing::new(require_len(sk_prf, SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN)?);
    let pk_seed = require_len(pk_seed, SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN)?;
    let (public_key, secret_key) =
        crypto_slh_dsa::derive_slh_dsa_sha2_128s_keypair(&sk_seed, &sk_prf, &pk_seed)
            .map_err(map_slh_dsa_error)?;
    keypair_to_js(public_key, secret_key)
}

#[wasm_bindgen(js_name = slhDsaSha2128sSign)]
/// Sign a message with SLH-DSA-SHA2-128s.
pub fn slh_dsa_sha2_128s_sign(
    secret_key: &Uint8Array,
    message: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let secret_key = Zeroizing::new(require_len(secret_key, SLH_DSA_SHA2_128S_SECRET_KEY_LEN)?);
    let signature = crypto_slh_dsa::sign_slh_dsa_sha2_128s(&secret_key, &message.to_vec())
        .map_err(map_slh_dsa_error)?;
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
    let public_key = require_len(public_key, SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN)?;
    let signature = require_len(signature, SLH_DSA_SHA2_128S_SIGNATURE_LEN)?;
    crypto_slh_dsa::verify_slh_dsa_sha2_128s(&public_key, &message.to_vec(), &signature)
        .map_err(map_slh_dsa_error)
}
