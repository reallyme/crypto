// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Cryptographically secure random-byte helpers backed by the operating system CSPRNG (`OsRng`), for nonces, salts, and key material. Fails closed if the OS entropy source is unavailable.

#![forbid(unsafe_code)]

mod constants;
mod generate;
mod rng;
mod types;

pub use constants::{AEAD_NONCE_12_LENGTH, ARGON2_SALT_16_LENGTH, ARGON2_SALT_32_LENGTH};
pub use generate::{
    generate_aead_nonce_12, generate_argon2_salt_16, generate_argon2_salt_32, generate_bytes,
};
pub use rng::{OsSecureRandom, SecureRandom};
pub use types::{AeadNonce12, Argon2Salt16, Argon2Salt32, RandomBytes};
