/*
 * SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ED25519_ABI_H
#define ED25519_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =======================
// Constants
// =======================

#define ED25519_PUBLIC_KEY_LEN    32
#define ED25519_SECRET_KEY_LEN    32
#define ED25519_SIGNATURE_LEN    64

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

crypto_status_t ed25519_generate_keypair(
    uint8_t* public_out,   // [32]
    uint8_t* secret_out    // [32]
);

// =======================
// Sign
// =======================

crypto_status_t ed25519_sign(
    const uint8_t* secret,     // [32] or [64]
    size_t secret_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out     // [64]
);

// =======================
// Verify
// =======================

crypto_status_t ed25519_verify(
    const uint8_t* public_key, // [32]
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,  // [64]
    int32_t* valid_out          // 1 = valid, 0 = invalid
);

// =======================
// Encoding (public key)
// =======================

crypto_status_t ed25519_encode_public_key(
    const uint8_t* public_key, // [32]
    uint8_t* out               // [32]
);

crypto_status_t ed25519_decode_public_key(
    const uint8_t* bytes,      // [32]
    uint8_t* out               // [32]
);

#ifdef __cplusplus
}
#endif

#endif // ED25519_ABI_H
