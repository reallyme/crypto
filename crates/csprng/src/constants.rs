// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Length in bytes of a generated AEAD nonce (12 bytes).
pub const AEAD_NONCE_12_LENGTH: usize = 12;
/// Length in bytes of a generated 16-byte Argon2 salt.
pub const ARGON2_SALT_16_LENGTH: usize = 16;
/// Length in bytes of a generated 32-byte Argon2 salt.
pub const ARGON2_SALT_32_LENGTH: usize = 32;
/// Length in bytes of generated AES-256-GCM key material.
pub const AES_256_GCM_KEY_LENGTH: usize = 32;
/// Length in bytes of a generated ML-KEM-1024 FIPS 203 seed (`d || z`).
pub const ML_KEM_1024_SEED_LENGTH: usize = 64;
/// Length in bytes of a generated ML-DSA-87 FIPS 204 seed.
pub const ML_DSA_87_SEED_LENGTH: usize = 32;
