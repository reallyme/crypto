// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    unsafe_code,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
#![cfg(all(feature = "native", feature = "aes", not(target_arch = "wasm32")))]

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use crypto_core::AeadAlgorithm;
use crypto_dispatch::error::AlgorithmError;
use crypto_dispatch::{aead_decrypt, aead_encrypt, AeadParams};

fn vector_key() -> [u8; 32] {
    [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
        0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
        0x83, 0x08,
    ]
}

fn vector_nonce() -> [u8; 12] {
    [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
    ]
}

fn vector_aad() -> Vec<u8> {
    hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").expect("vector aad must decode")
}

fn vector_plaintext() -> Vec<u8> {
    hex::decode(
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b39",
    )
    .expect("vector plaintext must decode")
}

fn vector_ciphertext_and_tag() -> Vec<u8> {
    hex::decode(
        "522dc1f099567d07f47f37a32a84427d\
         643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838\
         c5f61e6393ba7a0abcc9f662\
         76fc6ece0f4e1768cddf8853bb2d551b",
    )
    .expect("vector ciphertext must decode")
}

#[no_mangle]
/// # Safety
///
/// Caller must provide valid pointers and output buffers matching the lengths.
pub unsafe extern "C" fn aes256gcm_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    ciphertext_len_out: *mut usize,
) -> i32 {
    if key_len != 32 || nonce_len != 12 {
        return -1;
    }

    // SAFETY: Test-only FFI shim receives raw pointers and lengths from the
    // Rust adapter under test; all borrowed slices remain valid for this call.
    let key = unsafe { core::slice::from_raw_parts(key, key_len) };
    // SAFETY: See note above.
    let nonce = unsafe { core::slice::from_raw_parts(nonce, nonce_len) };
    // SAFETY: See note above.
    let aad = unsafe { core::slice::from_raw_parts(aad, aad_len) };
    // SAFETY: See note above.
    let plaintext = unsafe { core::slice::from_raw_parts(plaintext, plaintext_len) };

    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(cipher) => cipher,
        Err(_) => return -1,
    };

    let nonce_array: Nonce<U12> = match <[u8; 12]>::try_from(nonce) {
        Ok(value) => value.into(),
        Err(_) => return -2,
    };

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let encrypted = match cipher.encrypt(&nonce_array, payload) {
        Ok(bytes) => bytes,
        Err(_) => return -3,
    };

    if encrypted.len() > ciphertext_out_len {
        return -3;
    }

    // SAFETY: The output buffer and length come from caller contract.
    let out = unsafe { core::slice::from_raw_parts_mut(ciphertext_out, ciphertext_out_len) };
    out[..encrypted.len()].copy_from_slice(&encrypted);
    // SAFETY: Caller provided valid output length pointer.
    unsafe {
        *ciphertext_len_out = encrypted.len();
    }

    0
}

#[no_mangle]
/// # Safety
///
/// Caller must provide valid pointers and output buffers matching the lengths.
pub unsafe extern "C" fn aes256gcm_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    plaintext_out: *mut u8,
    plaintext_out_len: usize,
    plaintext_len_out: *mut usize,
) -> i32 {
    if key_len != 32 || nonce_len != 12 {
        return -1;
    }

    // SAFETY: Test-only FFI shim receives raw pointers and lengths from the
    // Rust adapter under test; all borrowed slices remain valid for this call.
    let key = unsafe { core::slice::from_raw_parts(key, key_len) };
    // SAFETY: See note above.
    let nonce = unsafe { core::slice::from_raw_parts(nonce, nonce_len) };
    // SAFETY: See note above.
    let aad = unsafe { core::slice::from_raw_parts(aad, aad_len) };
    // SAFETY: See note above.
    let ciphertext = unsafe { core::slice::from_raw_parts(ciphertext, ciphertext_len) };

    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(cipher) => cipher,
        Err(_) => return -1,
    };

    let nonce_array: Nonce<U12> = match <[u8; 12]>::try_from(nonce) {
        Ok(value) => value.into(),
        Err(_) => return -1,
    };

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = match cipher.decrypt(&nonce_array, payload) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };

    if plaintext.len() > plaintext_out_len {
        return -3;
    }

    // SAFETY: The output buffer and length come from caller contract.
    let out = unsafe { core::slice::from_raw_parts_mut(plaintext_out, plaintext_out_len) };
    out[..plaintext.len()].copy_from_slice(&plaintext);
    // SAFETY: Caller provided valid output length pointer.
    unsafe {
        *plaintext_len_out = plaintext.len();
    }

    0
}

#[test]
fn lane_runtime_aes_dispatch_matches_vector() {
    let key = vector_key();
    let nonce = vector_nonce();
    let aad = vector_aad();
    let plaintext = vector_plaintext();
    let expected = vector_ciphertext_and_tag();
    let params = AeadParams {
        key: &key,
        nonce: &nonce,
        aad: &aad,
    };

    let encrypted = aead_encrypt(AeadAlgorithm::Aes256Gcm, &params, &plaintext)
        .expect("dispatch encryption must succeed");

    assert_eq!(encrypted.as_slice(), expected.as_slice());

    let decrypted = aead_decrypt(AeadAlgorithm::Aes256Gcm, &params, &encrypted)
        .expect("dispatch decryption must succeed");

    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

#[test]
fn lane_runtime_aes_dispatch_rejects_tampered_ciphertext() {
    let key = vector_key();
    let nonce = vector_nonce();
    let aad = vector_aad();
    let mut tampered = vector_ciphertext_and_tag();
    tampered[0] ^= 0x80;
    let params = AeadParams {
        key: &key,
        nonce: &nonce,
        aad: &aad,
    };

    let err = aead_decrypt(AeadAlgorithm::Aes256Gcm, &params, &tampered)
        .expect_err("tampered ciphertext must fail");

    match err {
        AlgorithmError::Crypto(_) => {}
        _ => panic!("unexpected error variant for tampered ciphertext"),
    }
}
