// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
