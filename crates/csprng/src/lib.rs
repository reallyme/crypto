// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Cryptographically secure random-byte helpers backed by the operating system CSPRNG (`OsRng`), for nonces, salts, and key material. Fails closed if the OS entropy source is unavailable.

#![forbid(unsafe_code)]

mod constants;
mod generate;
mod rng;
mod types;

pub use constants::{
    AEAD_NONCE_12_LENGTH, AES_256_GCM_KEY_LENGTH, ARGON2_SALT_16_LENGTH, ARGON2_SALT_32_LENGTH,
    ML_DSA_87_SEED_LENGTH, ML_KEM_1024_SEED_LENGTH,
};
pub use generate::{
    generate_aead_nonce_12, generate_aes256_gcm_key, generate_argon2_salt_16,
    generate_argon2_salt_32, generate_bytes, generate_ml_dsa_87_seed, generate_ml_kem_1024_seed,
};
pub use rng::{OsSecureRandom, SecureRandom};
pub use types::{
    AeadNonce12, Aes256GcmKeyMaterial, Argon2Salt16, Argon2Salt32, MlDsa87Seed, MlKem1024Seed,
    RandomBytes,
};
