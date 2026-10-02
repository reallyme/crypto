// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ed25519 (RFC 8032) signatures. Verification rejects malleable signatures and non-canonical public keys.

mod validate_public_key;

pub use validate_public_key::validate_public_key_identity;

#[cfg(any(feature = "native", feature = "wasm"))]
mod native;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use native::{
    assert_public_key, decode_public_key, encode_public_key, generate_ed25519_keypair,
    generate_ed25519_keypair_from_seed, sign_ed25519, verify_ed25519,
};
