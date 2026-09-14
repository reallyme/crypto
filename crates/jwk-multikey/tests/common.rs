// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use envelopes_jwk::JwkOptions;

/// Standard JWK options for round-trip tests
pub fn default_opts() -> JwkOptions {
    JwkOptions {
        alg: true,
        use_sig: true,
        ..Default::default()
    }
}
