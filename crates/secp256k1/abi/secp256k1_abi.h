/*
 * SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SECP256K1_ABI_H
#define SECP256K1_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =======================
// Constants
// =======================

// Secret key: 32-byte scalar
#define SECP256K1_SECRET_KEY_LEN              32

// Public key (SEC1 encoding)
#define SECP256K1_PUBLIC_KEY_COMPRESSED_LEN   33
#define SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN 65

// secp256k1 signatures are fixed-size compact (r || s)
#define SECP256K1_SIGNATURE_LEN               64

// =======================
// Status codes
// =======================

typedef int32_t crypto_status_t;

#define CRYPTO_OK                   0
#define CRYPTO_INVALID_KEY         -1
#define CRYPTO_INVALID_SIGNATURE   -2
#define CRYPTO_INTERNAL_ERROR     -128

// =======================
// Keypair
// =======================
//
// Generates a secp256k1 keypair.
//
// Outputs:
//   - public_out:  33-byte compressed SEC1 public key
//   - secret_out:  32-byte private scalar
//
crypto_status_t secp256k1_generate_keypair(
    uint8_t* public_out,   // [SECP256K1_PUBLIC_KEY_COMPRESSED_LEN]
    uint8_t* secret_out    // [SECP256K1_SECRET_KEY_LEN]
);

// =======================
// Sign (ECDSA secp256k1)
// =======================
//
// Signs a message using ECDSA over secp256k1.
//
// Semantics:
//   - Message is hashed with SHA-256
//   - ECDSA signature is produced
//   - Signature is returned in compact form (r || s)
//   - low-S normalization IS enforced
//
crypto_status_t secp256k1_sign(
    const uint8_t* secret_key,     // [SECP256K1_SECRET_KEY_LEN]
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out         // [SECP256K1_SIGNATURE_LEN]
);

// =======================
// Verify (ECDSA secp256k1)
// =======================
//
// Verifies a compact secp256k1 ECDSA signature.
//
// Semantics:
//   - Message is hashed with SHA-256
//   - Signature is interpreted as (r || s)
//   - Both low-S and high-S signatures are accepted
//
crypto_status_t secp256k1_verify(
    const uint8_t* signature,      // [SECP256K1_SIGNATURE_LEN]
    const uint8_t* message,
    size_t message_len,
    const uint8_t* public_key_sec1, // [33] or [65]
    int32_t* valid_out               // 1 = valid, 0 = invalid
);

// =======================
// Encoding (SEC1 public key)
// =======================
//
// Identity encoding for compressed SEC1 keys.
//
// Compress:   65-byte uncompressed → 33-byte compressed
// Decompress: 33-byte compressed   → (x, y) coordinates
//
crypto_status_t secp256k1_encode_public_key(
    const uint8_t* public_key_compressed, // [SECP256K1_PUBLIC_KEY_COMPRESSED_LEN]
    uint8_t* out                          // [SECP256K1_PUBLIC_KEY_COMPRESSED_LEN]
);

crypto_status_t secp256k1_decode_public_key(
    const uint8_t* public_key_compressed, // [SECP256K1_PUBLIC_KEY_COMPRESSED_LEN]
    uint8_t* out                          // [SECP256K1_PUBLIC_KEY_COMPRESSED_LEN]
);

// =======================
// Decompression helper
// =======================
//
// Decompress compressed SEC1 public key into raw coordinates.
//
crypto_status_t secp256k1_decompress_public_key(
    const uint8_t* public_key_compressed, // [SECP256K1_PUBLIC_KEY_COMPRESSED_LEN]
    uint8_t* x_out,                        // [32]
    uint8_t* y_out                         // [32]
);

#ifdef __cplusplus
}
#endif

#endif // SECP256K1_ABI_H
