// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, missing_docs)]

//! Shared helpers for JWK envelope tests

/// Assert that a JCS string is canonical:
/// - valid JSON
/// - no whitespace
/// - keys sorted
#[allow(dead_code)]
pub fn assert_jcs(jcs: &str) {
    // Must be valid JSON
    let v: serde_json::Value = serde_json::from_str(jcs).expect("JCS output must be valid JSON");

    // JCS must be minified (no spaces or newlines)
    assert!(
        !jcs.contains(' ') && !jcs.contains('\n'),
        "JCS must be minified"
    );

    // Re-canonicalize and compare (idempotent)
    let recanonicalized =
        codec_jcs::canonicalize_trusted_json_value(&v).expect("re-canonicalization failed");

    assert_eq!(jcs, recanonicalized, "JCS output must be deterministic");
}
