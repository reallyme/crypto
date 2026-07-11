// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use crypto_core::MacAlgorithm;
use crypto_dispatch::{mac_authenticate, mac_verify, MacParams};

#[test]
fn hmac_sha256_authenticates_and_verifies() {
    let params = MacParams {
        key: b"reallyme hmac key",
    };
    let message = b"dispatch hmac message";

    let tag = mac_authenticate(MacAlgorithm::HmacSha256, &params, message).unwrap();
    mac_verify(MacAlgorithm::HmacSha256, &params, message, &tag).unwrap();

    let mut tampered = tag;
    tampered[0] ^= 0x01;
    assert!(mac_verify(MacAlgorithm::HmacSha256, &params, message, &tampered).is_err());
}

#[test]
fn hmac_sha512_rejects_wrong_tag_length() {
    let params = MacParams { key: b"key" };
    let short_tag = [0u8; 32];

    assert!(mac_verify(
        MacAlgorithm::HmacSha512,
        &params,
        b"dispatch hmac message",
        &short_tag
    )
    .is_err());
}
