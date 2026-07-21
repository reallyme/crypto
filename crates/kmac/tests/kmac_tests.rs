// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(any(feature = "native", feature = "wasm"))]
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use crypto_kmac::{
    derive_kmac256, Kmac256Key, KMAC256_MAX_CONTEXT_LENGTH, KMAC256_MAX_CUSTOMIZATION_LENGTH,
    KMAC256_MAX_KEY_LENGTH, KMAC256_MAX_OUTPUT_LENGTH, KMAC256_MIN_KEY_LENGTH,
};
use zeroize::Zeroizing;

#[test]
fn kmac256_matches_nist_sp800_185_sample() {
    let key_bytes: Vec<u8> = (0x40..=0x5f).collect();
    let key = Kmac256Key::from_slice(&key_bytes).expect("NIST key is valid");
    let output = derive_kmac256(
        &key,
        &[0x00, 0x01, 0x02, 0x03],
        b"My Tagged Application",
        64,
    )
    .expect("NIST sample derives");
    let expected = [
        0x20, 0xc5, 0x70, 0xc3, 0x13, 0x46, 0xf7, 0x03, 0xc9, 0xac, 0x36, 0xc6, 0x1c, 0x03, 0xcb,
        0x64, 0xc3, 0x97, 0x0d, 0x0c, 0xfc, 0x78, 0x7e, 0x9b, 0x79, 0x59, 0x9d, 0x27, 0x3a, 0x68,
        0xd2, 0xf7, 0xf6, 0x9d, 0x4c, 0xc3, 0xde, 0x9d, 0x10, 0x4a, 0x35, 0x16, 0x89, 0xf2, 0x7c,
        0xf6, 0xf5, 0x95, 0x1f, 0x01, 0x03, 0xf3, 0x3f, 0x4f, 0x24, 0x87, 0x10, 0x24, 0xd9, 0xc2,
        0x77, 0x73, 0xa8, 0xdd,
    ];
    assert_eq!(output.as_bytes(), expected);
}

#[test]
fn kmac256_rejects_short_keys_and_invalid_output_lengths() {
    let short = Zeroizing::new(vec![0u8; KMAC256_MIN_KEY_LENGTH - 1]);
    assert!(Kmac256Key::from_slice(&short).is_err());
    let oversized_key = Zeroizing::new(vec![0u8; KMAC256_MAX_KEY_LENGTH + 1]);
    assert!(Kmac256Key::from_slice(&oversized_key).is_err());

    let key =
        Kmac256Key::from_slice(&[0x42; KMAC256_MIN_KEY_LENGTH]).expect("minimum KMAC key is valid");
    assert!(derive_kmac256(&key, b"context", b"", 0).is_err());
    assert!(derive_kmac256(
        &key,
        b"context",
        b"",
        KMAC256_MAX_OUTPUT_LENGTH.saturating_add(1),
    )
    .is_err());
    let oversized_context = Zeroizing::new(vec![0u8; KMAC256_MAX_CONTEXT_LENGTH + 1]);
    assert!(derive_kmac256(&key, &oversized_context, b"", 32).is_err());
    let oversized_customization = Zeroizing::new(vec![0u8; KMAC256_MAX_CUSTOMIZATION_LENGTH + 1]);
    assert!(derive_kmac256(&key, b"", &oversized_customization, 32).is_err());
}
