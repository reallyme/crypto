// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz cryptographic key and signature serialization boundaries. This target
//! keeps a valid verification key for each large NIST curve so arbitrary bytes
//! reach the DER signature parser instead of stopping at public-key parsing.

#![no_main]

use std::sync::OnceLock;

use crypto_p384 as p384_primitive;
use crypto_p521 as p521_primitive;
use libfuzzer_sys::fuzz_target;
use reallyme_crypto::{p256, p384, p521, secp256k1};

static P384_PUBLIC_KEY: OnceLock<Option<Vec<u8>>> = OnceLock::new();
static P521_PUBLIC_KEY: OnceLock<Option<Vec<u8>>> = OnceLock::new();

fn p384_public_key() -> Option<&'static [u8]> {
    P384_PUBLIC_KEY
        .get_or_init(|| {
            let mut secret = [0u8; p384::P384_SECRET_KEY_LEN];
            let last = secret.len().checked_sub(1)?;
            secret[last] = 1;
            p384::generate_p384_keypair_from_secret_key(&secret)
                .ok()
                .map(|(public_key, _secret_key)| public_key)
        })
        .as_deref()
}

fn p521_public_key() -> Option<&'static [u8]> {
    P521_PUBLIC_KEY
        .get_or_init(|| {
            let mut secret = [0u8; p521::P521_SECRET_KEY_LEN];
            let last = secret.len().checked_sub(1)?;
            secret[last] = 1;
            p521::generate_p521_keypair_from_secret_key(&secret)
                .ok()
                .map(|(public_key, _secret_key)| public_key)
        })
        .as_deref()
}

fuzz_target!(|data: &[u8]| {
    // Strict SEC1 shape and curve validation for every exposed NIST helper.
    let _ = p256::compress_public_key(data);
    let _ = p256::decompress_public_key(data);
    let _ = p384::compress_public_key(data);
    let _ = p384::decompress_public_key(data);
    let _ = p521::compress_public_key(data);
    let _ = p521::decompress_public_key(data);

    // Direct ASN.1 and PEM imports are distinct public entrypoints. In
    // particular, direct DER input must keep the same resource cap as PEM.
    let _ = p256::private_key_from_pkcs8_der(data);
    let _ = p256::private_key_from_sec1_der(data);
    let _ = p256::public_key_from_spki_der(data);
    if let Ok(pem) = core::str::from_utf8(data) {
        let _ = p256::private_key_from_pkcs8_pem(pem);
        let _ = p256::private_key_from_sec1_pem(pem);
        let _ = p256::private_key_from_pem(pem);
        let _ = p256::public_key_from_spki_pem(pem);
    }

    // Exercise the canonical DER adapters and JOSE encoders.
    let _ = p256::p256_ecdsa_der_to_jose_signature(data);
    let _ = p256::p256_ecdsa_jose_signature_to_der(data);
    let _ = secp256k1::secp256k1_ecdsa_der_to_jose_signature(data);
    let _ = secp256k1::secp256k1_ecdsa_jose_signature_to_der(data);

    // secp256k1 exposes compressed SEC1 and x-only BIP-340 decoding.
    let _ = secp256k1::decode_public_key(data);
    let _ = secp256k1::decompress_public_key(data);
    let _ = secp256k1::decode_bip340_schnorr_public_key(data);

    if let Some(public_key) = p384_public_key() {
        let _ = p384_primitive::verify_p384_der_prehash(data, b"reallyme-fuzz", public_key);
    }
    if let Some(public_key) = p521_public_key() {
        let _ = p521_primitive::verify_p521_der_prehash(data, b"reallyme-fuzz", public_key);
    }

    // Secure Enclave handles are serialized opaque identifiers and need the
    // same no-panic property even though their parser is intentionally small.
    let _ = p256::decode_se_handle(data);
});
