// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RSA legacy FFI identities preserve their exact public numeric projection.

#![allow(missing_docs)]
use crypto_rsa::{RsaHash, RsaPublicKeyDerEncoding};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rsa_hash_ffi_ids_and_unknown_rejection_are_unchanged() {
    for (hash, id) in [
        (RsaHash::Sha1, 1),
        (RsaHash::Sha256, 2),
        (RsaHash::Sha384, 3),
        (RsaHash::Sha512, 4),
    ] {
        assert_eq!(hash.ffi_id(), id);
        assert_eq!(RsaHash::from_ffi_id(id), Some(hash));
    }
    for id in [0, 5, u32::MAX] {
        assert_eq!(RsaHash::from_ffi_id(id), None);
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rsa_der_ffi_ids_and_unknown_rejection_are_unchanged() {
    for (encoding, id) in [
        (RsaPublicKeyDerEncoding::Pkcs1, 1),
        (RsaPublicKeyDerEncoding::Spki, 2),
    ] {
        assert_eq!(encoding.ffi_id(), id);
        assert_eq!(RsaPublicKeyDerEncoding::from_ffi_id(id), Some(encoding));
    }
    for id in [0, 3, u32::MAX] {
        assert_eq!(RsaPublicKeyDerEncoding::from_ffi_id(id), None);
    }
}
