// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 (RFC 8032) signatures. Verification rejects malleable signatures and non-canonical public keys.

#[cfg(any(feature = "native", feature = "wasm"))]
mod native;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use native::{
    assert_public_key, decode_public_key, encode_public_key, generate_ed25519_keypair,
    generate_ed25519_keypair_from_seed, sign_ed25519, verify_ed25519,
};
