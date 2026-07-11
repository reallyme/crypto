// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Algorithm dispatch and structural validation.
//!
//! This crate is the runtime seam between an [`Algorithm`](crypto_core::Algorithm)
//! selector and the concrete primitive that implements it. Given an
//! algorithm value it routes keygen, sign/verify, key agreement, KEM
//! encapsulate/decapsulate, AEAD, and hashing to the matching primitive
//! adapter, and it binds public keys to their multicodec/multikey
//! encodings.
//!
//! Two safety properties are enforced here rather than left to callers:
//! [`verify`] fails closed — an invalid signature is an
//! [`AlgorithmError::SignatureInvalid`], never `Ok(false)` — and every
//! secret returned (generated private keys, shared secrets, decapsulated
//! secrets) is carried in a zeroizing wrapper. Length and key-shape checks are
//! performed by the selected primitive's typed constructors and are exercised
//! by dispatch-level negative tests so algorithm routing cannot silently
//! truncate, pad, or reinterpret caller bytes.
//!
//! Constant-time behavior for authentication comparisons is inherited from the
//! wrapped primitive crates. Dispatch does not reimplement tag, MAC, or
//! signature comparison logic; it routes to the primitive verifier and maps
//! the verifier's typed failure into this crate's fail-closed result.

// Core modules
/// Error type returned by dispatch operations.
pub mod error;
/// Adapter traits implemented by each algorithm primitive.
pub mod traits;

// Algorithm adapters
/// Per-algorithm adapters wiring selectors to concrete primitives.
pub mod algorithms;
/// Hashing dispatch.
pub mod hash;
/// Message authentication code dispatch.
pub mod mac;

// Dispatch entry points
/// Keypair generation with multikey-encoded public keys.
pub mod keypair;
/// Multicodec/multikey encoding of public keys.
pub mod multikey;
/// Runtime dispatch entry points for sign/verify, key agreement, KEM, and AEAD.
pub mod registry;
/// Structural validation of verification-method multikeys.
pub mod validation;

// Re-export error type
pub use error::AlgorithmError;
pub use traits::{AeadParams, MacParams};

// Re-export public dispatch API

pub use hash::hash_digest;
pub use mac::{mac_authenticate, mac_verify};
pub use registry::{
    aead_decrypt, aead_encrypt, derive_shared_secret, generate_keypair, kem_decapsulate,
    kem_encapsulate, sign, verify,
};

pub use keypair::{generate_multikey_keypair, GeneratedKeypair};

pub use multikey::public_key_to_multikey;

pub use validation::validate_verification_method_multikey;
