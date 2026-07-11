// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::encoding::{ML_KEM_512_PUBLIC_KEY_LEN, ML_KEM_512_SECRET_KEY_LEN};
use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroizing;

/// ML-KEM-512 ciphertext length in bytes (FIPS 203).
const ML_KEM_512_CIPHERTEXT_LEN: usize = 768;
/// ML-KEM-512 shared-secret length in bytes.
const ML_KEM_512_SHARED_SECRET_LEN: usize = 32;

fn kem_failure(kind: crypto_core::KemFailureKind) -> CryptoError {
    CryptoError::KemFailure { kind }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = mlKem512Encapsulate)]
    fn js_mlkem512_encapsulate(public_key: Uint8Array) -> JsValue;

    #[wasm_bindgen(js_name = mlKem512Decapsulate)]
    fn js_mlkem512_decapsulate(ciphertext: Uint8Array, secret_key: Uint8Array) -> Uint8Array;
}

/// Encapsulate a shared secret to an ML-KEM-512 public key.
///
/// Returns (ciphertext, shared_secret)
pub fn ml_kem_512_encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    if public_key.len() != ML_KEM_512_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let pk = Uint8Array::from(public_key);
    let v = js_mlkem512_encapsulate(pk);
    let obj = js_sys::Object::from(v);

    let ct = js_sys::Reflect::get(&obj, &JsValue::from_str("cipherText"))
        .map_err(|_| kem_failure(crypto_core::KemFailureKind::EncapsulateFailed))?;
    let ss = js_sys::Reflect::get(&obj, &JsValue::from_str("sharedSecret"))
        .map_err(|_| kem_failure(crypto_core::KemFailureKind::EncapsulateFailed))?;

    let ct = Uint8Array::new(&ct).to_vec();
    let ss = Zeroizing::new(Uint8Array::new(&ss).to_vec());

    // Fail closed if the JS bridge returned wrong-length material: a
    // degenerate (empty/short) ciphertext or shared secret must never be
    // accepted as a successful encapsulation.
    if ct.len() != ML_KEM_512_CIPHERTEXT_LEN || ss.len() != ML_KEM_512_SHARED_SECRET_LEN {
        return Err(kem_failure(crypto_core::KemFailureKind::EncapsulateFailed));
    }

    Ok((ct, ss))
}

/// Decapsulate a shared secret from an ML-KEM-512 ciphertext.
pub fn ml_kem_512_decapsulate(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Validate input lengths before crossing the JS boundary — the native
    // lane rejects these too, and a wrong length must not reach the bridge.
    if ciphertext.len() != ML_KEM_512_CIPHERTEXT_LEN {
        return Err(kem_failure(crypto_core::KemFailureKind::DecapsulateFailed));
    }
    if secret_key.len() != ML_KEM_512_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let ct = Uint8Array::from(ciphertext);
    let sk = Uint8Array::from(secret_key);

    let shared_secret = Zeroizing::new(js_mlkem512_decapsulate(ct, sk).to_vec());
    // Fail closed on a degenerate output: implicit rejection must still
    // return a full-length pseudorandom secret, never an empty/short one.
    if shared_secret.len() != ML_KEM_512_SHARED_SECRET_LEN {
        return Err(kem_failure(crypto_core::KemFailureKind::DecapsulateFailed));
    }
    Ok(shared_secret)
}
