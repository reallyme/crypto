// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Length in bytes of an AES-128 key-encryption key.
pub const AES_128_KW_KEK_LENGTH: usize =
    crypto_core::contract_constants::aes_kw::AES_128_KW_KEK_LENGTH;
/// Length in bytes of an AES-192 key-encryption key.
pub const AES_192_KW_KEK_LENGTH: usize =
    crypto_core::contract_constants::aes_kw::AES_192_KW_KEK_LENGTH;
/// Length in bytes of an AES-256 key-encryption key.
pub const AES_256_KW_KEK_LENGTH: usize =
    crypto_core::contract_constants::aes_kw::AES_256_KW_KEK_LENGTH;
/// RFC 3394 AES-KW data block length in bytes.
pub const AES_KW_BLOCK_LENGTH: usize = crypto_core::contract_constants::aes_kw::AES_KW_BLOCK_LENGTH;
/// Length in bytes of the RFC 3394 integrity-check register.
pub const AES_KW_INTEGRITY_CHECK_LENGTH: usize =
    crypto_core::contract_constants::aes_kw::AES_KW_INTEGRITY_CHECK_LENGTH;
/// Minimum plaintext key-data length accepted by RFC 3394 AES-KW.
pub const AES_KW_MIN_KEY_DATA_LENGTH: usize =
    crypto_core::contract_constants::aes_kw::AES_KW_MIN_KEY_DATA_LENGTH;
/// Minimum wrapped-key length for accepted RFC 3394 AES-KW inputs.
pub const AES_KW_MIN_WRAPPED_KEY_LENGTH: usize =
    crypto_core::contract_constants::aes_kw::AES_KW_MIN_WRAPPED_KEY_LENGTH;
/// Maximum accepted key-data length in bytes.
///
/// AES-KW itself can process far larger inputs, but key wrapping is for compact
/// cryptographic key material. The cap keeps FFI and package boundary
/// allocation behavior deterministic.
pub const AES_KW_MAX_KEY_DATA_LENGTH: usize =
    crypto_core::contract_constants::aes_kw::AES_KW_MAX_KEY_DATA_LENGTH;
