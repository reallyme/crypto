// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz the RSA public-key DER parser reached through signature verification.
//! Property: parsing an untrusted DER public key (PKCS#1 or SPKI) and a
//! caller-supplied signature must never panic — verification fails closed with
//! a typed error or a `false` result.

#![no_main]

use crypto_rsa::{
    verify_rsa_pkcs1v15, verify_rsa_pss, RsaHash, RsaPssParams, RsaPublicKeyDerEncoding,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First byte selects the DER encoding and hash so the corpus explores both
    // PKCS#1 and SPKI parsing paths and every digest identifier.
    let (selector, der) = match data.split_first() {
        Some(parts) => parts,
        None => return,
    };
    let encoding = if selector & 1 == 0 {
        RsaPublicKeyDerEncoding::Pkcs1
    } else {
        RsaPublicKeyDerEncoding::Spki
    };
    let hash = match (selector >> 1) & 0b11 {
        0 => RsaHash::Sha1,
        1 => RsaHash::Sha256,
        2 => RsaHash::Sha384,
        _ => RsaHash::Sha512,
    };

    // The whole remaining input is treated as the untrusted DER public key; a
    // fixed-length dummy signature drives the length checks and PKCS#1 padding
    // parser without needing a matching key.
    let signature = [0u8; 256];
    let _ = verify_rsa_pkcs1v15(der, encoding, hash, b"reallyme-fuzz", &signature);
    let pss = RsaPssParams {
        message_hash: hash,
        mgf1_hash: hash,
        salt_len: 32,
    };
    let _ = verify_rsa_pss(der, encoding, pss, b"reallyme-fuzz", &signature);
});
