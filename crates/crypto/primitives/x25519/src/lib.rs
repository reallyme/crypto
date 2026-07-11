// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! X25519 key agreement (RFC 7748).

#[cfg(feature = "native")]
mod native;

#[cfg(feature = "native")]
pub use native::{
    assert_public_key, decode_public_key, derive_x25519_shared_secret, encode_public_key,
    generate_x25519_keypair, generate_x25519_keypair_from_seed,
};

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
mod wasm;

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
pub use wasm::{
    assert_public_key, decode_public_key, derive_x25519_shared_secret, encode_public_key,
    generate_x25519_keypair, X25519_PUBLIC_KEY_LEN,
};
