// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Conversion between ReallyMe JWK public keys and multikey strings.

mod error;
mod to_jwk;
mod to_multikey;

pub use error::JwkMultikeyError;

pub use to_jwk::multikey_to_jwk;
pub use to_multikey::jwk_to_multikey;
