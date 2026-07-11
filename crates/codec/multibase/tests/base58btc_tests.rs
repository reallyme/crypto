// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
use codec_multibase::{base58btc_decode, base58btc_encode};

#[test]
fn roundtrip() {
    let data = b"hello world";
    let s = base58btc_encode(data);
    let out = base58btc_decode(&s).unwrap();
    assert_eq!(out, data);
}

#[test]
fn leading_zeros() {
    let data = [0u8, 0u8, 1u8];
    let s = base58btc_encode(&data);
    assert!(s.starts_with("11"));
    let out = base58btc_decode(&s).unwrap();
    assert_eq!(out, data);
}

#[test]
fn roundtrip_pq_sized_payload() {
    let data: Vec<u8> = (0..2_700).map(|i| u8::try_from(i % 251).unwrap()).collect();
    let s = base58btc_encode(&data);
    let out = base58btc_decode(&s).unwrap();
    assert_eq!(out, data);
}

#[test]
fn rejects_invalid_char() {
    assert!(base58btc_decode("0").is_err()); // '0' not in alphabet
}
