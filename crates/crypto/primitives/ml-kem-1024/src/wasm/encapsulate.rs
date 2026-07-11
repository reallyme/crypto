// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::encoding::{ML_KEM_1024_PUBLIC_KEY_LEN, ML_KEM_1024_SECRET_KEY_LEN};
use crypto_core::CryptoError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// ML-KEM-1024 ciphertext length in bytes (FIPS 203).
const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1568;
/// ML-KEM-1024 shared-secret length in bytes.
const ML_KEM_1024_SHARED_SECRET_LEN: usize = 32;

fn kem_failure(kind: crypto_core::KemFailureKind) -> CryptoError {
    CryptoError::KemFailure { kind }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = mlKem1024Encapsulate)]
    fn js_mlkem1024_encapsulate(public_key: Uint8Array) -> JsValue;

    #[wasm_bindgen(js_name = mlKem1024Decapsulate)]
    fn js_mlkem1024_decapsulate(ciphertext: Uint8Array, secret_key: Uint8Array) -> Uint8Array;
}

/// Encapsulate a shared secret to an ML-KEM-1024 public key.
///
/// Returns (ciphertext, shared_secret)
pub fn ml_kem_1024_encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    if public_key.len() != ML_KEM_1024_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let pk = Uint8Array::from(public_key);
    let v = js_mlkem1024_encapsulate(pk);

    let obj = js_sys::Object::from(v);

    let ct = js_sys::Reflect::get(&obj, &JsValue::from_str("cipherText"))
        .map_err(|_| kem_failure(crypto_core::KemFailureKind::EncapsulateFailed))?;
    let ss = js_sys::Reflect::get(&obj, &JsValue::from_str("sharedSecret"))
        .map_err(|_| kem_failure(crypto_core::KemFailureKind::EncapsulateFailed))?;

    let ct = Uint8Array::new(&ct).to_vec();
    let ss = Zeroizing::new(Uint8Array::new(&ss).to_vec());

    // Fail closed if the JS bridge returned wrong-length material.
    if ct.len() != ML_KEM_1024_CIPHERTEXT_LEN || ss.len() != ML_KEM_1024_SHARED_SECRET_LEN {
        return Err(kem_failure(crypto_core::KemFailureKind::EncapsulateFailed));
    }

    Ok((ct, ss))
}

/// Decapsulate a shared secret from an ML-KEM-1024 ciphertext.
pub fn ml_kem_1024_decapsulate(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Validate input lengths before crossing the JS boundary.
    if ciphertext.len() != ML_KEM_1024_CIPHERTEXT_LEN {
        return Err(kem_failure(crypto_core::KemFailureKind::DecapsulateFailed));
    }
    if secret_key.len() != ML_KEM_1024_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let ct = Uint8Array::from(ciphertext);
    let sk = Uint8Array::from(secret_key);

    let shared_secret = Zeroizing::new(js_mlkem1024_decapsulate(ct, sk).to_vec());
    // Fail closed on a degenerate output.
    if shared_secret.len() != ML_KEM_1024_SHARED_SECRET_LEN {
        return Err(kem_failure(crypto_core::KemFailureKind::DecapsulateFailed));
    }
    Ok(shared_secret)
}
