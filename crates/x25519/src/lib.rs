// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! X25519 key agreement (RFC 7748).

#[cfg(any(feature = "native", feature = "wasm"))]
mod native;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use native::{
    assert_public_key, decode_public_key, derive_x25519_shared_secret, encode_public_key,
    generate_x25519_keypair, generate_x25519_keypair_from_seed, X25519_PUBLIC_KEY_LEN,
};
