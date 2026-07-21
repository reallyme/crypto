// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Bounded PBKDF2 key derivation conforming to RFC 8018.
//!
//! PBKDF2 is intentionally exposed as a bounded primitive. New password
//! storage and unlock flows should prefer the workspace Argon2id profiles.

#![forbid(unsafe_code)]

mod constants;
#[cfg(any(feature = "native", feature = "wasm"))]
mod derive_key;
mod types;

pub use constants::{
    PBKDF2_MAX_ITERATIONS, PBKDF2_MAX_OUTPUT_LENGTH, PBKDF2_MAX_PASSWORD_LENGTH,
    PBKDF2_MAX_SALT_LENGTH, PBKDF2_MIN_OUTPUT_LENGTH, PBKDF2_MIN_PASSWORD_LENGTH,
    PBKDF2_MIN_SALT_LENGTH, PBKDF2_MODERN_MIN_ITERATIONS, PBKDF2_STANDARD_MIN_ITERATIONS,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use derive_key::{derive_key, Pbkdf2Request};
pub use types::{Pbkdf2Iterations, Pbkdf2Output, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Salt};
