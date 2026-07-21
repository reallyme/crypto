// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! KMAC256 key derivation using the KMAC primitive defined by NIST SP 800-185.
//!
//! Native and WebAssembly lanes intentionally use the same implementation so
//! protocol adapters derive identical bytes on every supported runtime.

#![forbid(unsafe_code)]

mod algorithm;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use self::algorithm::derive_kmac256;
pub use self::algorithm::{
    Kmac256Key, Kmac256Output, KMAC256_MAX_CONTEXT_LENGTH, KMAC256_MAX_CUSTOMIZATION_LENGTH,
    KMAC256_MAX_KEY_LENGTH, KMAC256_MAX_OUTPUT_LENGTH, KMAC256_MIN_KEY_LENGTH,
};
