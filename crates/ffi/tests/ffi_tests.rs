// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(unsafe_code)]
#![allow(clippy::expect_used)]

use core::ptr::NonNull;
use std::fs;
use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crypto_ffi::aes256_gcm;
use crypto_ffi::aes256_gcm_siv;
use crypto_ffi::aes_kw;
use crypto_ffi::argon2id;
use crypto_ffi::bip340_schnorr;
use crypto_ffi::constant_time;
use crypto_ffi::csprng;
use crypto_ffi::ed25519;
use crypto_ffi::hkdf;
use crypto_ffi::hmac;
use crypto_ffi::hpke;
use crypto_ffi::kmac;
use crypto_ffi::ml_dsa_44;
use crypto_ffi::ml_dsa_65;
use crypto_ffi::ml_dsa_87;
use crypto_ffi::ml_kem_1024;
use crypto_ffi::ml_kem_512;
use crypto_ffi::ml_kem_768;
use crypto_ffi::p256;
use crypto_ffi::p384;
use crypto_ffi::p521;
use crypto_ffi::pbkdf2;
use crypto_ffi::rsa as rsa_ffi;
use crypto_ffi::secp256k1;
use crypto_ffi::sha2;
use crypto_ffi::sha2_256;
use crypto_ffi::sha3;
use crypto_ffi::sha3_256;
use crypto_ffi::slh_dsa;
use crypto_ffi::status;
use crypto_ffi::x25519;
use crypto_ffi::x_wing;
use serde_json::Value;

fn decode_base64url(value: &str) -> Result<Vec<u8>, crypto_core::CryptoError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| crypto_core::CryptoError::InvalidKey)
}

fn load_shared_vector(name: &str) -> Value {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir
        .ancestors()
        .map(|directory| directory.join("vectors").join(name))
        .find(|candidate| candidate.exists())
        .expect("shared vector fixture must exist");
    let json = fs::read_to_string(&candidate).expect("shared vector JSON must be readable");
    serde_json::from_str(&json).expect("shared vector JSON must parse")
}

fn vector_string<'a>(vector: &'a Value, field: &str) -> &'a str {
    vector
        .get(field)
        .and_then(Value::as_str)
        .expect("shared vector field must be a string")
}

fn vector_bytes(vector: &Value, field: &str) -> Vec<u8> {
    decode_base64url(vector_string(vector, field)).expect("shared vector field must be base64url")
}

include!("ffi_tests/abi_header.rs");
include!("ffi_tests/pointer_boundary.rs");
include!("ffi_tests/signature_fail_closed.rs");
include!("ffi_tests/supplied_key_constructors.rs");
include!("ffi_tests/rsa.rs");
include!("ffi_tests/mac_hash.rs");
include!("ffi_tests/aead_and_key_wrap.rs");
include!("ffi_tests/kdf.rs");
include!("ffi_tests/random_and_constant_time.rs");
include!("ffi_tests/classical_signature.rs");
include!("ffi_tests/schnorr_x25519_and_pq_signature.rs");
include!("ffi_tests/kem_and_hpke.rs");
