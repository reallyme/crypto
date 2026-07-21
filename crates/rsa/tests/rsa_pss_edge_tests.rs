// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! RFC 8017 coverage for PSS encoded messages one byte shorter than the modulus.

#![allow(clippy::expect_used)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use crypto_rsa::{verify_rsa_pss, RsaHash, RsaPssParams, RsaPublicKeyDerEncoding};

// Independently generated with OpenSSL from a 1025-bit RSA key. For this key,
// RFC 8017 defines emBits = 1024 and emLen = 128 while the RSA signature and
// modulus are 129 bytes. This is the exact boundary that a k-byte-only PSS
// implementation rejects incorrectly.
const PUBLIC_KEY_PKCS1_DER: &str = "MIGJAoGBAT2xGH3a2TEFZ5QzqDasWUbE3bqGfOSapZHM1/VReRgLDT5mh9qFEYCCC9c9gZdVpT3JH+UXa47WC133wCohGgihZJfSSjd8F59GdXBOlN1SPESfAO+byULl7/pyBYqj3lkiNo2yA73AGMQW279ZrZUHapliQYhTFs1K7DK0w+l/AgMBAAE=";
const EMPTY_MESSAGE_PSS_SHA256_SIGNATURE: &str = "AJw/2MC05uvkQewI8UcKYVB6XpaJ2Fu9qwBCMBlIlVVP5I9/gnmBs8QMZavjoRReZnURZkLpACVIF1tRO+eCUheclpKEBqEog9ECpwmXYVR11kWREyTfeNJyXaYAM7jxYLptdfeDVYZ6SmJrtXGoG5rdSBQIMxeqiAP0UJ/7qZd5";

#[test]
fn pss_accepts_rfc8017_em_len_one_byte_shorter_than_modulus() {
    let public_key = decode(PUBLIC_KEY_PKCS1_DER);
    let signature = decode(EMPTY_MESSAGE_PSS_SHA256_SIGNATURE);

    verify_rsa_pss(
        &public_key,
        RsaPublicKeyDerEncoding::Pkcs1,
        sha256_pss_params(),
        &[],
        &signature,
    )
    .expect("valid 1025-bit RSA-PSS signature verifies");
}

#[test]
fn pss_non_byte_aligned_fixture_rejects_wrong_message_salt_and_signature() {
    let public_key = decode(PUBLIC_KEY_PKCS1_DER);
    let signature = decode(EMPTY_MESSAGE_PSS_SHA256_SIGNATURE);

    assert!(verify_rsa_pss(
        &public_key,
        RsaPublicKeyDerEncoding::Pkcs1,
        sha256_pss_params(),
        b"wrong message",
        &signature,
    )
    .is_err());
    assert!(verify_rsa_pss(
        &public_key,
        RsaPublicKeyDerEncoding::Pkcs1,
        RsaPssParams {
            salt_len: 31,
            ..sha256_pss_params()
        },
        &[],
        &signature,
    )
    .is_err());

    let mut tampered = signature;
    tampered[1] ^= 1;
    assert!(verify_rsa_pss(
        &public_key,
        RsaPublicKeyDerEncoding::Pkcs1,
        sha256_pss_params(),
        &[],
        &tampered,
    )
    .is_err());
}

fn sha256_pss_params() -> RsaPssParams {
    RsaPssParams {
        message_hash: RsaHash::Sha256,
        mgf1_hash: RsaHash::Sha256,
        salt_len: 32,
    }
}

fn decode(value: &str) -> Vec<u8> {
    STANDARD.decode(value).expect("fixture base64 decodes")
}
