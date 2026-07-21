/*
 * SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ML_DSA_65_ABI_H
#define ML_DSA_65_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =======================
// Constants
// =======================
//
// ML-DSA-65 (ML-DSA / ML-DSA-65)
// Fixed-size public keys, seed secrets, and signatures
//

#define ML_DSA_65_PUBLIC_KEY_LEN    1952
#define ML_DSA_65_SECRET_SEED_LEN   32
#define ML_DSA_65_SIGNATURE_LEN     3309

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
// Generates an ML-DSA-65 keypair.
//
// Outputs:
//   - public_out:  1952-byte public key
//   - secret_seed_out:  32-byte FIPS seed secret
//
crypto_status_t ml_dsa_65_generate_keypair(
    uint8_t* public_out,       // [ML_DSA_65_PUBLIC_KEY_LEN]
    uint8_t* secret_seed_out   // [ML_DSA_65_SECRET_SEED_LEN]
);

// =======================
// Sign (ML-DSA-65)
// =======================
//
// Signs a message using ML-DSA-65.
//
// Semantics:
//   - Raw message (no hashing)
//   - Detached signature
//   - Fixed-size signature (3309 bytes)
//
crypto_status_t ml_dsa_65_sign(
    const uint8_t* secret_seed,  // [ML_DSA_65_SECRET_SEED_LEN]
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out       // [ML_DSA_65_SIGNATURE_LEN]
);

// =======================
// Verify (ML-DSA-65)
// =======================
//
// Verifies an ML-DSA-65 detached signature.
//
crypto_status_t ml_dsa_65_verify(
    const uint8_t* public_key,   // [ML_DSA_65_PUBLIC_KEY_LEN]
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,    // [ML_DSA_65_SIGNATURE_LEN]
    int32_t* valid_out            // 1 = valid, 0 = invalid
);

// =======================
// Encoding (public key)
// =======================
//
// Identity encoding helpers (for symmetry with other algorithms).
//
crypto_status_t ml_dsa_65_encode_public_key(
    const uint8_t* public_key,   // [ML_DSA_65_PUBLIC_KEY_LEN]
    uint8_t* out                 // [ML_DSA_65_PUBLIC_KEY_LEN]
);

crypto_status_t ml_dsa_65_decode_public_key(
    const uint8_t* public_key,   // [ML_DSA_65_PUBLIC_KEY_LEN]
    uint8_t* out                 // [ML_DSA_65_PUBLIC_KEY_LEN]
);

#ifdef __cplusplus
}
#endif

#endif // ML_DSA_65_ABI_H
