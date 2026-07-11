/*
 * SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef REALLYME_CRYPTO_FFI_H
#define REALLYME_CRYPTO_FFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t rm_crypto_status_t;

#define RM_CRYPTO_OK                         0
#define RM_CRYPTO_INVALID_ARGUMENT          -1
#define RM_CRYPTO_INVALID_KEY               -2
#define RM_CRYPTO_INVALID_SIGNATURE         -3
#define RM_CRYPTO_INVALID_CIPHERTEXT        -4
#define RM_CRYPTO_BUFFER_TOO_SMALL          -5
#define RM_CRYPTO_AUTHENTICATION_FAILED     -6
#define RM_CRYPTO_INTERNAL_ERROR          -128

/*
 * FFI memory contract
 *
 * Every byte input is passed as (const uint8_t* ptr, size_t len). Every byte
 * output is passed as (uint8_t* ptr, size_t len), with produced lengths written
 * through separate non-null size_t* outputs where the function declares one.
 *
 * - A byte pointer may be NULL only when its paired length is 0.
 * - Non-empty byte pairs must point to one initialized, valid allocation of at
 *   least len bytes for the full call.
 * - Output byte pairs must be writable and exclusively owned by the caller for
 *   the full call.
 * - byte lengths greater than isize::MAX are rejected before Rust slice
 *   construction.
 * - size_t* and int32_t* output pointers must be non-NULL and naturally
 *   aligned for their pointee type.
 * - Input and output regions for the same call must not overlap unless a
 *   function explicitly documents in-place operation. No current ReallyMe
 *   Crypto FFI function supports in-place operation.
 */

#define RM_CRYPTO_AES256_GCM_KEY_LEN        32
#define RM_CRYPTO_AES256_GCM_NONCE_LEN      12
#define RM_CRYPTO_AES256_GCM_TAG_LEN        16
#define RM_CRYPTO_AES256_KW_KEK_LEN         32
#define RM_CRYPTO_AES_KW_BLOCK_LEN          8
#define RM_CRYPTO_AES_KW_INTEGRITY_LEN      8
#define RM_CRYPTO_AES_KW_MIN_KEY_DATA_LEN   16
#define RM_CRYPTO_AES_KW_MIN_WRAPPED_KEY_LEN 24
#define RM_CRYPTO_AES_KW_MAX_KEY_DATA_LEN   4096
#define RM_CRYPTO_AES256_GCM_SIV_KEY_LEN    32
#define RM_CRYPTO_AES256_GCM_SIV_NONCE_LEN  12
#define RM_CRYPTO_AES256_GCM_SIV_TAG_LEN    16
#define RM_CRYPTO_ARGON2ID_DERIVED_KEY_LEN  32
#define RM_CRYPTO_CSPRNG_AEAD_NONCE_12_LEN  12
#define RM_CRYPTO_CSPRNG_ARGON2_SALT_16_LEN 16
#define RM_CRYPTO_CSPRNG_ARGON2_SALT_32_LEN 32
#define RM_CRYPTO_HKDF_SUITE_SHA2_256       1
#define RM_CRYPTO_HKDF_SUITE_SHA3_256       2
#define RM_CRYPTO_HPKE_SUITE_P256_SHA256_AES256GCM 1
#define RM_CRYPTO_HPKE_SUITE_X25519_SHA256_CHACHA20_POLY1305 2
#define RM_CRYPTO_HPKE_ENCAPSULATED_KEY_MAX_LEN 65
#define RM_CRYPTO_HPKE_P256_PUBLIC_KEY_LEN  65
#define RM_CRYPTO_HPKE_P256_PRIVATE_KEY_LEN 32
#define RM_CRYPTO_HPKE_X25519_PUBLIC_KEY_LEN 32
#define RM_CRYPTO_HPKE_X25519_PRIVATE_KEY_LEN 32
#define RM_CRYPTO_HPKE_AEAD_TAG_LEN         16
#define RM_CRYPTO_HMAC_SUITE_SHA256         1
#define RM_CRYPTO_HMAC_SUITE_SHA512         2
#define RM_CRYPTO_HMAC_SHA256_TAG_LEN       32
#define RM_CRYPTO_HMAC_SHA512_TAG_LEN       64
#define RM_CRYPTO_PBKDF2_PASSWORD_MIN_LEN   1
#define RM_CRYPTO_PBKDF2_PASSWORD_MAX_LEN   4096
#define RM_CRYPTO_PBKDF2_SALT_MIN_LEN       1
#define RM_CRYPTO_PBKDF2_SALT_MAX_LEN       4096
#define RM_CRYPTO_PBKDF2_ITERATIONS_MIN     1
#define RM_CRYPTO_PBKDF2_OUTPUT_MIN_LEN     1
#define RM_CRYPTO_PBKDF2_OUTPUT_MAX_LEN     4096
#define RM_CRYPTO_SHA2_256_DIGEST_LEN       32
#define RM_CRYPTO_SHA2_384_DIGEST_LEN       48
#define RM_CRYPTO_SHA2_512_DIGEST_LEN       64
#define RM_CRYPTO_SHA3_224_DIGEST_LEN       28
#define RM_CRYPTO_SHA3_256_DIGEST_LEN       32
#define RM_CRYPTO_SHA3_384_DIGEST_LEN       48
#define RM_CRYPTO_SHA3_512_DIGEST_LEN       64
#define RM_CRYPTO_ED25519_PUBLIC_KEY_LEN    32
#define RM_CRYPTO_ED25519_SECRET_KEY_LEN    32
#define RM_CRYPTO_ED25519_SIGNATURE_LEN     64
#define RM_CRYPTO_P256_SECRET_KEY_LEN       32
#define RM_CRYPTO_P256_PUBLIC_KEY_COMPRESSED_LEN    33
#define RM_CRYPTO_P256_PUBLIC_KEY_UNCOMPRESSED_LEN  65
#define RM_CRYPTO_P256_SHARED_SECRET_LEN            32
#define RM_CRYPTO_P256_SIGNATURE_DER_MAX_LEN        80
#define RM_CRYPTO_P384_SECRET_KEY_LEN       48
#define RM_CRYPTO_P384_PUBLIC_KEY_COMPRESSED_LEN    49
#define RM_CRYPTO_P384_PUBLIC_KEY_UNCOMPRESSED_LEN  97
#define RM_CRYPTO_P384_SIGNATURE_DER_MAX_LEN        104
#define RM_CRYPTO_P521_SECRET_KEY_LEN       66
#define RM_CRYPTO_P521_PUBLIC_KEY_COMPRESSED_LEN    67
#define RM_CRYPTO_P521_PUBLIC_KEY_UNCOMPRESSED_LEN  133
#define RM_CRYPTO_P521_SIGNATURE_DER_MAX_LEN        144
#define RM_CRYPTO_RSA_HASH_SHA1                      1
#define RM_CRYPTO_RSA_HASH_SHA256                    2
#define RM_CRYPTO_RSA_HASH_SHA384                    3
#define RM_CRYPTO_RSA_HASH_SHA512                    4
#define RM_CRYPTO_RSA_PUBLIC_KEY_ENCODING_PKCS1_DER  1
#define RM_CRYPTO_RSA_PUBLIC_KEY_ENCODING_SPKI_DER   2
#define RM_CRYPTO_RSA_PUBLIC_KEY_DER_MAX_LEN         4096
#define RM_CRYPTO_RSA_SIGNATURE_MAX_LEN              1024
#define RM_CRYPTO_SECP256K1_SECRET_KEY_LEN           32
#define RM_CRYPTO_SECP256K1_PUBLIC_KEY_COMPRESSED_LEN 33
#define RM_CRYPTO_SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN 65
#define RM_CRYPTO_SECP256K1_SIGNATURE_LEN            64
#define RM_CRYPTO_BIP340_SCHNORR_PUBLIC_KEY_LEN      32
#define RM_CRYPTO_BIP340_SCHNORR_MESSAGE_LEN         32
#define RM_CRYPTO_BIP340_SCHNORR_AUX_RAND_LEN        32
#define RM_CRYPTO_BIP340_SCHNORR_SIGNATURE_LEN       64
#define RM_CRYPTO_X25519_PUBLIC_KEY_LEN      32
#define RM_CRYPTO_X25519_SECRET_KEY_LEN      32
#define RM_CRYPTO_X25519_SHARED_SECRET_LEN   32
#define RM_CRYPTO_ML_DSA_44_PUBLIC_KEY_LEN   1312
#define RM_CRYPTO_ML_DSA_44_SECRET_SEED_LEN  32
#define RM_CRYPTO_ML_DSA_44_SIGNATURE_LEN    2420
#define RM_CRYPTO_ML_DSA_65_PUBLIC_KEY_LEN   1952
#define RM_CRYPTO_ML_DSA_65_SECRET_SEED_LEN  32
#define RM_CRYPTO_ML_DSA_65_SIGNATURE_LEN    3309
#define RM_CRYPTO_ML_DSA_87_PUBLIC_KEY_LEN   2592
#define RM_CRYPTO_ML_DSA_87_SECRET_SEED_LEN  32
#define RM_CRYPTO_ML_DSA_87_SIGNATURE_LEN    4627
#define RM_CRYPTO_ML_KEM_512_PUBLIC_KEY_LEN  800
#define RM_CRYPTO_ML_KEM_512_SECRET_KEY_LEN  64
#define RM_CRYPTO_ML_KEM_512_CIPHERTEXT_LEN  768
#define RM_CRYPTO_ML_KEM_512_SHARED_SECRET_LEN 32
#define RM_CRYPTO_ML_KEM_768_PUBLIC_KEY_LEN  1184
#define RM_CRYPTO_ML_KEM_768_SECRET_KEY_LEN  64
#define RM_CRYPTO_ML_KEM_768_CIPHERTEXT_LEN  1088
#define RM_CRYPTO_ML_KEM_768_SHARED_SECRET_LEN 32
#define RM_CRYPTO_ML_KEM_1024_PUBLIC_KEY_LEN 1568
#define RM_CRYPTO_ML_KEM_1024_SECRET_KEY_LEN 64
#define RM_CRYPTO_ML_KEM_1024_CIPHERTEXT_LEN 1568
#define RM_CRYPTO_ML_KEM_1024_SHARED_SECRET_LEN 32
#define RM_CRYPTO_SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN 32
#define RM_CRYPTO_SLH_DSA_SHA2_128S_SECRET_KEY_LEN 64
#define RM_CRYPTO_SLH_DSA_SHA2_128S_SIGNATURE_LEN 7856
#define RM_CRYPTO_SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN 16
#define RM_CRYPTO_X_WING_SECRET_KEY_LEN      32
#define RM_CRYPTO_X_WING_ENCAPS_SEED_LEN     64
#define RM_CRYPTO_X_WING_SHARED_SECRET_LEN   32
#define RM_CRYPTO_X_WING_768_PUBLIC_KEY_LEN  1216
#define RM_CRYPTO_X_WING_768_CIPHERTEXT_LEN  1120
#define RM_CRYPTO_X_WING_1024_PUBLIC_KEY_LEN 1600
#define RM_CRYPTO_X_WING_1024_CIPHERTEXT_LEN 1600

rm_crypto_status_t rm_crypto_sha2_256_digest(
    const uint8_t* message,
    size_t message_len,
    uint8_t* digest_out,
    size_t digest_out_len
);

rm_crypto_status_t rm_crypto_sha2_384_digest(
    const uint8_t* message,
    size_t message_len,
    uint8_t* digest_out,
    size_t digest_out_len
);

rm_crypto_status_t rm_crypto_sha2_512_digest(
    const uint8_t* message,
    size_t message_len,
    uint8_t* digest_out,
    size_t digest_out_len
);

rm_crypto_status_t rm_crypto_sha3_224_digest(
    const uint8_t* message,
    size_t message_len,
    uint8_t* digest_out,
    size_t digest_out_len
);

rm_crypto_status_t rm_crypto_sha3_256_digest(
    const uint8_t* message,
    size_t message_len,
    uint8_t* digest_out,
    size_t digest_out_len
);

rm_crypto_status_t rm_crypto_sha3_384_digest(
    const uint8_t* message,
    size_t message_len,
    uint8_t* digest_out,
    size_t digest_out_len
);

rm_crypto_status_t rm_crypto_sha3_512_digest(
    const uint8_t* message,
    size_t message_len,
    uint8_t* digest_out,
    size_t digest_out_len
);

rm_crypto_status_t rm_crypto_aes256_gcm_encrypt(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    size_t* ciphertext_len_out
);

rm_crypto_status_t rm_crypto_aes256_gcm_decrypt(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext_out,
    size_t plaintext_out_len,
    size_t* plaintext_len_out
);

rm_crypto_status_t rm_crypto_aes256_kw_wrap_key(
    const uint8_t* kek,
    size_t kek_len,
    const uint8_t* key_data,
    size_t key_data_len,
    uint8_t* wrapped_out,
    size_t wrapped_out_len,
    size_t* wrapped_len_out
);

rm_crypto_status_t rm_crypto_aes256_kw_unwrap_key(
    const uint8_t* kek,
    size_t kek_len,
    const uint8_t* wrapped,
    size_t wrapped_len,
    uint8_t* key_data_out,
    size_t key_data_out_len,
    size_t* key_data_len_out
);

rm_crypto_status_t rm_crypto_aes256_gcm_siv_encrypt(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    size_t* ciphertext_len_out
);

rm_crypto_status_t rm_crypto_aes256_gcm_siv_decrypt(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext_out,
    size_t plaintext_out_len,
    size_t* plaintext_len_out
);

rm_crypto_status_t rm_crypto_argon2id_derive_key(
    uint32_t kdf_version,
    const uint8_t* secret,
    size_t secret_len,
    const uint8_t* salt,
    size_t salt_len,
    uint8_t* derived_key_out,
    size_t derived_key_out_len
);

rm_crypto_status_t rm_crypto_hkdf_derive(
    uint32_t suite,
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* output_out,
    size_t output_out_len
);

rm_crypto_status_t rm_crypto_pbkdf2_hmac_sha256_derive_key(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t* output_out,
    size_t output_out_len
);

rm_crypto_status_t rm_crypto_pbkdf2_hmac_sha512_derive_key(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t* output_out,
    size_t output_out_len
);

rm_crypto_status_t rm_crypto_hpke_seal_base(
    uint32_t suite,
    const uint8_t* recipient_public_key,
    size_t recipient_public_key_len,
    const uint8_t* info,
    size_t info_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* encapsulated_key_out,
    size_t encapsulated_key_out_len,
    size_t* encapsulated_key_len_out,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    size_t* ciphertext_len_out
);

rm_crypto_status_t rm_crypto_hpke_open_base(
    uint32_t suite,
    const uint8_t* encapsulated_key,
    size_t encapsulated_key_len,
    const uint8_t* recipient_private_key,
    size_t recipient_private_key_len,
    const uint8_t* info,
    size_t info_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext_out,
    size_t plaintext_out_len,
    size_t* plaintext_len_out
);

rm_crypto_status_t rm_crypto_hmac_authenticate(
    uint32_t suite,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* tag_out,
    size_t tag_out_len
);

rm_crypto_status_t rm_crypto_hmac_verify(
    uint32_t suite,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* tag,
    size_t tag_len
);

rm_crypto_status_t rm_crypto_csprng_generate_bytes(
    uint8_t* output_out,
    size_t output_out_len
);

rm_crypto_status_t rm_crypto_csprng_generate_aead_nonce_12(
    uint8_t* output_out,
    size_t output_out_len
);

rm_crypto_status_t rm_crypto_csprng_generate_argon2_salt_16(
    uint8_t* output_out,
    size_t output_out_len
);

rm_crypto_status_t rm_crypto_csprng_generate_argon2_salt_32(
    uint8_t* output_out,
    size_t output_out_len
);

rm_crypto_status_t rm_crypto_constant_time_equal(
    const uint8_t* left,
    size_t left_len,
    const uint8_t* right,
    size_t right_len,
    int32_t* equal_out
);

rm_crypto_status_t rm_crypto_ed25519_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_ed25519_generate_keypair_from_seed(
    const uint8_t* seed,
    size_t seed_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_ed25519_sign(
    const uint8_t* secret,
    size_t secret_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,
    size_t signature_out_len
);

rm_crypto_status_t rm_crypto_ed25519_verify(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len
);

rm_crypto_status_t rm_crypto_ed25519_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ed25519_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_p256_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_p256_generate_keypair_from_secret_key(
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_p256_sign_der_prehash(
    const uint8_t* secret_key,
    size_t secret_key_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,
    size_t signature_out_len,
    size_t* signature_len_out
);

rm_crypto_status_t rm_crypto_p256_verify_der_prehash(
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* public_key,
    size_t public_key_len
);

rm_crypto_status_t rm_crypto_p256_derive_shared_secret(
    const uint8_t* secret_key,
    size_t secret_key_len,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_p256_compress_public_key(
    const uint8_t* public_key_uncompressed,
    size_t public_key_uncompressed_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_p256_decompress_public_key(
    const uint8_t* public_key_compressed,
    size_t public_key_compressed_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_p384_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_p384_generate_keypair_from_secret_key(
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_p384_sign_der_prehash(
    const uint8_t* secret_key,
    size_t secret_key_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,
    size_t signature_out_len,
    size_t* signature_len_out
);

rm_crypto_status_t rm_crypto_p384_verify_der_prehash(
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* public_key,
    size_t public_key_len
);

rm_crypto_status_t rm_crypto_p384_compress_public_key(
    const uint8_t* public_key_uncompressed,
    size_t public_key_uncompressed_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_p384_decompress_public_key(
    const uint8_t* public_key_compressed,
    size_t public_key_compressed_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_p521_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_p521_generate_keypair_from_secret_key(
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_p521_sign_der_prehash(
    const uint8_t* secret_key,
    size_t secret_key_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,
    size_t signature_out_len,
    size_t* signature_len_out
);

rm_crypto_status_t rm_crypto_p521_verify_der_prehash(
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* public_key,
    size_t public_key_len
);

rm_crypto_status_t rm_crypto_p521_compress_public_key(
    const uint8_t* public_key_uncompressed,
    size_t public_key_uncompressed_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_p521_decompress_public_key(
    const uint8_t* public_key_compressed,
    size_t public_key_compressed_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_rsa_verify_pkcs1v15(
    const uint8_t* public_key_der,
    size_t public_key_der_len,
    uint32_t public_key_encoding,
    uint32_t hash_suite,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len
);

rm_crypto_status_t rm_crypto_rsa_verify_pss(
    const uint8_t* public_key_der,
    size_t public_key_der_len,
    uint32_t public_key_encoding,
    uint32_t message_hash_suite,
    uint32_t mgf1_hash_suite,
    size_t salt_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len
);

rm_crypto_status_t rm_crypto_secp256k1_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_secp256k1_generate_keypair_from_secret_key(
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_secp256k1_sign(
    const uint8_t* secret_key,
    size_t secret_key_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,
    size_t signature_out_len
);

rm_crypto_status_t rm_crypto_secp256k1_verify(
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* public_key,
    size_t public_key_len
);

rm_crypto_status_t rm_crypto_secp256k1_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_secp256k1_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_secp256k1_decompress_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* x_out,
    size_t x_out_len,
    uint8_t* y_out,
    size_t y_out_len
);

rm_crypto_status_t rm_crypto_bip340_schnorr_derive_public_key(
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* public_key_out,
    size_t public_key_out_len
);

rm_crypto_status_t rm_crypto_bip340_schnorr_sign(
    const uint8_t* secret_key,
    size_t secret_key_len,
    const uint8_t* message32,
    size_t message32_len,
    const uint8_t* aux_rand32,
    size_t aux_rand32_len,
    uint8_t* signature_out,
    size_t signature_out_len
);

rm_crypto_status_t rm_crypto_bip340_schnorr_verify(
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* message32,
    size_t message32_len,
    const uint8_t* public_key_xonly,
    size_t public_key_xonly_len
);

rm_crypto_status_t rm_crypto_bip340_schnorr_encode_public_key(
    const uint8_t* public_key_xonly,
    size_t public_key_xonly_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_bip340_schnorr_decode_public_key(
    const uint8_t* public_key_xonly,
    size_t public_key_xonly_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_x25519_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_x25519_generate_keypair_from_seed(
    const uint8_t* seed,
    size_t seed_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_x25519_derive_shared_secret(
    const uint8_t* secret_key,
    size_t secret_key_len,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_x25519_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_x25519_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_44_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_seed_out,
    size_t secret_seed_out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_44_generate_keypair_from_seed(
    const uint8_t* secret_seed,
    size_t secret_seed_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_seed_out,
    size_t secret_seed_out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_44_sign(
    const uint8_t* secret_seed,
    size_t secret_seed_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,
    size_t signature_out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_44_verify(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len
);

rm_crypto_status_t rm_crypto_ml_dsa_44_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_44_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_slh_dsa_sha2_128s_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_key_out,
    size_t secret_key_out_len
);

rm_crypto_status_t rm_crypto_slh_dsa_sha2_128s_derive_keypair(
    const uint8_t* sk_seed,
    size_t sk_seed_len,
    const uint8_t* sk_prf,
    size_t sk_prf_len,
    const uint8_t* pk_seed,
    size_t pk_seed_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_key_out,
    size_t secret_key_out_len
);

rm_crypto_status_t rm_crypto_slh_dsa_sha2_128s_sign(
    const uint8_t* secret_key,
    size_t secret_key_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,
    size_t signature_out_len
);

rm_crypto_status_t rm_crypto_slh_dsa_sha2_128s_verify(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len
);

rm_crypto_status_t rm_crypto_slh_dsa_sha2_128s_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_slh_dsa_sha2_128s_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_65_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_seed_out,
    size_t secret_seed_out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_65_generate_keypair_from_seed(
    const uint8_t* secret_seed,
    size_t secret_seed_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_seed_out,
    size_t secret_seed_out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_65_sign(
    const uint8_t* secret_seed,
    size_t secret_seed_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,
    size_t signature_out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_65_verify(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len
);

rm_crypto_status_t rm_crypto_ml_dsa_65_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_65_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_87_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_seed_out,
    size_t secret_seed_out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_87_generate_keypair_from_seed(
    const uint8_t* secret_seed,
    size_t secret_seed_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_seed_out,
    size_t secret_seed_out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_87_sign(
    const uint8_t* secret_seed,
    size_t secret_seed_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out,
    size_t signature_out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_87_verify(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len
);

rm_crypto_status_t rm_crypto_ml_dsa_87_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_dsa_87_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_kem_512_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_512_generate_keypair_from_seed(
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_512_encapsulate(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_512_encapsulate_derand(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* randomness,
    size_t randomness_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_512_decapsulate(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_512_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_kem_512_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_kem_768_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_768_generate_keypair_from_seed(
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_768_encapsulate(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_768_encapsulate_derand(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* randomness,
    size_t randomness_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_768_decapsulate(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_768_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_kem_768_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_kem_1024_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_1024_generate_keypair_from_seed(
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_1024_encapsulate(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_1024_encapsulate_derand(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* randomness,
    size_t randomness_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_1024_decapsulate(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_ml_kem_1024_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_ml_kem_1024_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_x_wing_768_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_x_wing_768_generate_keypair_derand(
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* public_out,
    size_t public_out_len
);

rm_crypto_status_t rm_crypto_x_wing_768_encapsulate(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_x_wing_768_encapsulate_derand(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* seed,
    size_t seed_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_x_wing_768_decapsulate(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_x_wing_768_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_x_wing_768_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_x_wing_1024_generate_keypair(
    uint8_t* public_out,
    size_t public_out_len,
    uint8_t* secret_out,
    size_t secret_out_len
);

rm_crypto_status_t rm_crypto_x_wing_1024_generate_keypair_derand(
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* public_out,
    size_t public_out_len
);

rm_crypto_status_t rm_crypto_x_wing_1024_encapsulate(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_x_wing_1024_encapsulate_derand(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* seed,
    size_t seed_len,
    uint8_t* ciphertext_out,
    size_t ciphertext_out_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_x_wing_1024_decapsulate(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_out_len
);

rm_crypto_status_t rm_crypto_x_wing_1024_encode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

rm_crypto_status_t rm_crypto_x_wing_1024_decode_public_key(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* out,
    size_t out_len
);

#ifdef __cplusplus
}
#endif

#endif
