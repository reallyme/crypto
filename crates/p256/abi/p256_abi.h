/*
 * SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef P256_ABI_H
#define P256_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =======================
// Constants
// =======================

// Secret key: 32-byte scalar
#define P256_SECRET_KEY_LEN              32

// Public key (SEC1 encoding)
#define P256_PUBLIC_KEY_COMPRESSED_LEN   33
#define P256_PUBLIC_KEY_UNCOMPRESSED_LEN 65
#define P256_SHARED_SECRET_LEN           32

// DER signatures are variable length. Two maximally padded 33-byte ASN.1
// INTEGER values plus their tags/lengths and the SEQUENCE header require 72.
#define P256_SIGNATURE_DER_MAX_LEN       72

// =======================
// Status codes
// =======================

typedef int32_t crypto_status_t;

#define CRYPTO_OK                   0
#define CRYPTO_INVALID_KEY         -1
#define CRYPTO_INVALID_SIGNATURE   -2
#define CRYPTO_INTERNAL_ERROR     -128

// =======================
// Secure Enclave (P-256)
// =======================
//
// These APIs manage and use a Secure Enclave-backed P-256 key identified by a tag.
// The private key is never exported; Rust passes the tag back to sign.
//

crypto_status_t p256_se_generate_keypair(
    const uint8_t* tag_bytes,
    size_t tag_len,
    uint8_t* public_out              // [P256_PUBLIC_KEY_COMPRESSED_LEN]
);

crypto_status_t p256_se_sign_der_prehash(
    const uint8_t* tag_bytes,
    size_t tag_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,          // [P256_SIGNATURE_DER_MAX_LEN]
    size_t signature_out_len,        // must be >= P256_SIGNATURE_DER_MAX_LEN
    size_t* signature_len_out        // actual DER length written
);

crypto_status_t p256_se_delete_key(
    const uint8_t* tag_bytes,
    size_t tag_len
);



// =======================
// Keypair
// =======================
//
// Generates a P-256 keypair.
//
// Outputs:
//   - public_out:  33-byte compressed SEC1 public key
//   - secret_out:  32-byte private scalar
//
crypto_status_t p256_generate_keypair(
    uint8_t* public_out,   // [P256_PUBLIC_KEY_COMPRESSED_LEN]
    uint8_t* secret_out    // [P256_SECRET_KEY_LEN]
);

// =======================
// Sign (ECDSA P-256)
// =======================
//
// Signs a message using ECDSA over the P-256 curve with SHA-256.
//
// Semantics:
//   - Message is hashed with SHA-256
//   - ECDSA signature is produced
//   - Signature is returned in ASN.1 DER format
//
// The caller MUST provide a signature_out buffer of at least
// P256_SIGNATURE_DER_MAX_LEN bytes.
//
crypto_status_t p256_sign_der_prehash(
    const uint8_t* secret_key,     // [P256_SECRET_KEY_LEN]
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,        // [P256_SIGNATURE_DER_MAX_LEN]
    size_t signature_out_len,      // must be >= P256_SIGNATURE_DER_MAX_LEN
    size_t* signature_len_out      // actual DER length written
);

// =======================
// Verify (ECDSA P-256)
// =======================
//
// Verifies a DER-encoded ECDSA P-256 signature.
//
// Semantics:
//   - Message is hashed with SHA-256
//   - Signature is parsed from DER
//   - Both low-S and high-S signatures are accepted
//
crypto_status_t p256_verify_der_prehash(
    const uint8_t* signature_der,
    size_t signature_der_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* public_key_sec1, // [33] or [65]
    int32_t* valid_out               // 1 = valid, 0 = invalid
);

// =======================
// Key agreement (ECDH P-256)
// =======================
//
// Computes the raw 32-byte SEC 1 ECDH x-coordinate. Callers must feed this
// value into a protocol-specific KDF before using it as symmetric key material.
//
crypto_status_t p256_derive_shared_secret(
    const uint8_t* secret_key,        // [P256_SECRET_KEY_LEN]
    size_t secret_key_len,
    const uint8_t* public_key_sec1,   // [33] or [65]
    size_t public_key_sec1_len,
    uint8_t* shared_secret_out,       // [P256_SHARED_SECRET_LEN]
    size_t shared_secret_out_len
);

// =======================
// Encoding (SEC1 public key)
// =======================
//
// Compress:   65-byte uncompressed → 33-byte compressed
// Decompress: 33-byte compressed   → 65-byte uncompressed
//
crypto_status_t p256_compress_public_key(
    const uint8_t* public_key_uncompressed, // [P256_PUBLIC_KEY_UNCOMPRESSED_LEN]
    uint8_t* out                             // [P256_PUBLIC_KEY_COMPRESSED_LEN]
);

crypto_status_t p256_decompress_public_key(
    const uint8_t* public_key_compressed,   // [P256_PUBLIC_KEY_COMPRESSED_LEN]
    uint8_t* out                             // [P256_PUBLIC_KEY_UNCOMPRESSED_LEN]
);

#ifdef __cplusplus
}
#endif

#endif // P256_ABI_H
