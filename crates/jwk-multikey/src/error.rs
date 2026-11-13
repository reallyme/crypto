// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical, data-free errors for JWK and multikey conversion.

/// Canonical crypto error returned by public-key envelope conversion.
pub use crypto_core::CryptoError as JwkMultikeyError;
