// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 (RFC 8032) signatures. Verification rejects malleable signatures and non-canonical public keys.

#[cfg(feature = "native")]
mod native;

#[cfg(feature = "native")]
pub use native::{
    assert_public_key, decode_public_key, encode_public_key, generate_ed25519_keypair,
    generate_ed25519_keypair_from_seed, sign_ed25519, verify_ed25519,
};

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
mod wasm;

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
pub use wasm::{
    assert_public_key, decode_public_key, encode_public_key, generate_ed25519_keypair,
    sign_ed25519, verify_ed25519,
};
