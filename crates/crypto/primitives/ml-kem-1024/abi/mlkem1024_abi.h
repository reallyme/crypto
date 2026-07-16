/*
 * SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLKEM1024_ABI_H
#define MLKEM1024_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =======================
// Constants
// =======================
//
// FIPS 203: ML-KEM-1024
// Fixed-size keys, ciphertext, and shared secret.
//

#define MLKEM1024_PUBLIC_KEY_LEN     1568
#define MLKEM1024_SECRET_KEY_LEN       64
#define MLKEM1024_CIPHERTEXT_LEN     1568
#define MLKEM1024_SHARED_SECRET_LEN    32

// =======================
// Status codes
// =======================

typedef int32_t crypto_status_t;

#define CRYPTO_OK                   0
#define CRYPTO_INVALID_KEY         -1
#define CRYPTO_INVALID_CIPHERTEXT  -2
#define CRYPTO_INTERNAL_ERROR     -128

// =======================
// Keypair
// =======================
//
// Generates an ML-KEM-1024 keypair.
//
// Outputs:
//   - public_out:  1568-byte public key
//   - secret_out:    64-byte secret seed
//
crypto_status_t mlkem1024_generate_keypair(
    uint8_t* public_out,   // [MLKEM1024_PUBLIC_KEY_LEN]
    uint8_t* secret_out    // [MLKEM1024_SECRET_KEY_LEN]
);

// =======================
// Encapsulate (ML-KEM-1024)
// =======================
//
// Encapsulates to a recipient public key.
//
// Outputs:
//   - ciphertext_out:    1568 bytes
//   - shared_secret_out: 32 bytes
//
crypto_status_t mlkem1024_encapsulate(
    const uint8_t* public_key,      // [MLKEM1024_PUBLIC_KEY_LEN]
    uint8_t* ciphertext_out,        // [MLKEM1024_CIPHERTEXT_LEN]
    uint8_t* shared_secret_out      // [MLKEM1024_SHARED_SECRET_LEN]
);

// =======================
// Decapsulate (ML-KEM-1024)
// =======================
//
// Decapsulates a shared secret from ciphertext and secret seed.
//
// Output:
//   - shared_secret_out: 32 bytes
//
crypto_status_t mlkem1024_decapsulate(
    const uint8_t* ciphertext,      // [MLKEM1024_CIPHERTEXT_LEN]
    const uint8_t* secret_key,      // [MLKEM1024_SECRET_KEY_LEN]
    uint8_t* shared_secret_out      // [MLKEM1024_SHARED_SECRET_LEN]
);

// =======================
// Encoding (public key)
// =======================
//
// Identity encoding helpers (for symmetry with other algorithms).
//
crypto_status_t mlkem1024_encode_public_key(
    const uint8_t* public_key,      // [MLKEM1024_PUBLIC_KEY_LEN]
    uint8_t* out                    // [MLKEM1024_PUBLIC_KEY_LEN]
);

crypto_status_t mlkem1024_decode_public_key(
    const uint8_t* public_key,      // [MLKEM1024_PUBLIC_KEY_LEN]
    uint8_t* out                    // [MLKEM1024_PUBLIC_KEY_LEN]
);

#ifdef __cplusplus
}
#endif

#endif // MLKEM1024_ABI_H
