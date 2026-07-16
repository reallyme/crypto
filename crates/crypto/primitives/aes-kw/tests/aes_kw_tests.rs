// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use crypto_aes_kw::{unwrap_key, wrap_key, Aes256KwKek, AES_256_KW_KEK_LENGTH};
use hex_literal::hex;

#[test]
fn rfc_3394_256_bit_kek_256_bit_key_data_vector_matches() {
    let kek = Aes256KwKek::from_slice(&hex!(
        "000102030405060708090A0B0C0D0E0F"
        "101112131415161718191A1B1C1D1E1F"
    ))
    .unwrap();
    let key_data = hex!(
        "00112233445566778899AABBCCDDEEFF"
        "000102030405060708090A0B0C0D0E0F"
    );
    let expected_wrapped = hex!(
        "28C9F404C4B810F4CBCCB35CFB87F826"
        "3F5786E2D80ED326CBC7F0E71A99F43B"
        "FB988B9B7A02DD21"
    );

    let wrapped = wrap_key(&kek, &key_data).unwrap();
    assert_eq!(wrapped.as_bytes(), expected_wrapped);

    let unwrapped = unwrap_key(&kek, wrapped.as_bytes()).unwrap();
    assert_eq!(unwrapped.as_bytes(), key_data);
}

#[test]
fn unwrap_rejects_tampering_and_wrong_kek() {
    let kek = Aes256KwKek::from_slice(&[0x11; AES_256_KW_KEK_LENGTH]).unwrap();
    let wrong_kek = Aes256KwKek::from_slice(&[0x22; AES_256_KW_KEK_LENGTH]).unwrap();
    let key_data = [0x33; 32];
    let wrapped = wrap_key(&kek, &key_data).unwrap();

    let mut tampered = wrapped.clone().into_vec();
    tampered[0] ^= 0x01;
    assert!(unwrap_key(&kek, &tampered).is_err());
    assert!(unwrap_key(&wrong_kek, wrapped.as_bytes()).is_err());
}

#[test]
fn invalid_lengths_are_rejected() {
    assert!(Aes256KwKek::from_slice(&[0u8; AES_256_KW_KEK_LENGTH - 1]).is_err());
    let kek = Aes256KwKek::from_slice(&[0x44; AES_256_KW_KEK_LENGTH]).unwrap();

    assert!(wrap_key(&kek, &[0u8; 8]).is_err());
    assert!(wrap_key(&kek, &[0u8; 17]).is_err());
    assert!(unwrap_key(&kek, &[0u8; 16]).is_err());
    assert!(unwrap_key(&kek, &[0u8; 25]).is_err());
}
