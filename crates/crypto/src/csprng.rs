// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Keep the umbrella's reviewed 0.3.9 randomness surface explicit. Callers
// receive the stable types and functions without a wildcard crate export.
pub use crypto_csprng::{
    generate_aead_nonce_12, generate_argon2_salt_16, generate_argon2_salt_32, generate_bytes,
    AeadNonce12, Argon2Salt16, Argon2Salt32, OsSecureRandom, RandomBytes, SecureRandom,
    AEAD_NONCE_12_LENGTH, ARGON2_SALT_16_LENGTH, ARGON2_SALT_32_LENGTH,
};
