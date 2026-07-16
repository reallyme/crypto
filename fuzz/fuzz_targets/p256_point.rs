// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz the P-256 SEC1 point decompressor and the ECDSA DER signature parser.
//! Property: decompressing an untrusted compressed point, and verifying an
//! untrusted DER signature against a fixed valid public key, must never panic —
//! both fail closed with a typed error or a `false` result.

#![no_main]

use libfuzzer_sys::fuzz_target;

// The P-256 base point G in SEC1 compressed form (0x02 || Gx). A fixed, valid
// public key lets the corpus drive the DER signature parser deeply instead of
// bailing out on a malformed key.
const P256_G_COMPRESSED: [u8; 33] = [
    0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96,
];

fuzz_target!(|data: &[u8]| {
    // Untrusted compressed point → decompression parser.
    let _ = crypto_p256::decompress_p256(data);
    // Untrusted DER signature → ECDSA DER parser (fixed valid key, fixed msg).
    let _ = crypto_p256::verify_p256_der_prehash(data, b"reallyme-fuzz", &P256_G_COMPRESSED);
});
