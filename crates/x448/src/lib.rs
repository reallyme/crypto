// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! X448 key agreement (RFC 7748).

#![forbid(unsafe_code)]

#[cfg(feature = "native")]
mod agreement;
mod constants;
#[cfg(feature = "native")]
mod keypair;
#[cfg(feature = "native")]
mod material;

#[cfg(feature = "native")]
pub use agreement::derive_x448_shared_secret;
pub use constants::{X448_PRIVATE_KEY_LEN, X448_PUBLIC_KEY_LEN, X448_SHARED_SECRET_LEN};
#[cfg(feature = "native")]
pub use keypair::{generate_x448_keypair, generate_x448_keypair_from_seed};
#[cfg(feature = "native")]
pub use material::{X448PrivateKey, X448PublicKey, X448SharedSecret};
