/*
 * SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef X25519_ABI_H
#define X25519_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =======================
// Constants
// =======================
//
// X25519 (RFC 7748)
// Fixed-size keys and shared secret.
//

#define X25519_PUBLIC_KEY_LEN     32
#define X25519_SECRET_KEY_LEN     32
#define X25519_SHARED_SECRET_LEN  32

// =======================
// Status codes
// =======================

typedef int32_t crypto_status_t;

#define CRYPTO_OK                   0
#define CRYPTO_INVALID_KEY         -1
#define CRYPTO_INTERNAL_ERROR     -128

// =======================
// Keypair
// =======================
//
// Generates an X25519 keypair.
//
// Outputs:
//   - public_out:  32-byte public key
//   - secret_out:  32-byte secret key
//
crypto_status_t x25519_generate_keypair(
    uint8_t* public_out,   // [X25519_PUBLIC_KEY_LEN]
    uint8_t* secret_out    // [X25519_SECRET_KEY_LEN]
);

// =======================
// Derive (X25519)
// =======================
//
// Derives a shared secret using X25519.
//
// shared_secret = X25519(secret_key, public_key)
//
// Output:
//   - shared_secret_out: 32 bytes
//
crypto_status_t x25519_derive_shared_secret(
    const uint8_t* secret_key,      // [X25519_SECRET_KEY_LEN]
    const uint8_t* public_key,      // [X25519_PUBLIC_KEY_LEN]
    uint8_t* shared_secret_out      // [X25519_SHARED_SECRET_LEN]
);

// =======================
// Encoding (public key)
// =======================
//
// Identity encoding helpers (for symmetry with other algorithms).
//
crypto_status_t x25519_encode_public_key(
    const uint8_t* public_key,      // [X25519_PUBLIC_KEY_LEN]
    uint8_t* out                    // [X25519_PUBLIC_KEY_LEN]
);

crypto_status_t x25519_decode_public_key(
    const uint8_t* public_key,      // [X25519_PUBLIC_KEY_LEN]
    uint8_t* out                    // [X25519_PUBLIC_KEY_LEN]
);

#ifdef __cplusplus
}
#endif

#endif // X25519_ABI_H
