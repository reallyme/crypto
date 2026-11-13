// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Length in bytes of an AES-256-GCM-SIV key (32 bytes / 256 bits).
pub const AES_256_GCM_SIV_KEY_LENGTH: usize =
    crypto_core::contract_constants::aes256_gcm_siv::AES_256_GCM_SIV_KEY_LENGTH;
/// Length in bytes of an AES-256-GCM-SIV nonce (12 bytes / 96 bits).
pub const AES_256_GCM_SIV_NONCE_LENGTH: usize =
    crypto_core::contract_constants::aes256_gcm_siv::AES_256_GCM_SIV_NONCE_LENGTH;
/// Length in bytes of an AES-256-GCM-SIV authentication tag (16 bytes / 128 bits).
pub const AES_256_GCM_SIV_TAG_LENGTH: usize =
    crypto_core::contract_constants::aes256_gcm_siv::AES_256_GCM_SIV_TAG_LENGTH;
