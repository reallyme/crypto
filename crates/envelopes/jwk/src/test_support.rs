// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

/// Assert a string is valid RFC 8785 JCS canonical JSON.
#[allow(clippy::panic)]
pub fn assert_jcs(jcs: &str) {
    let Ok(v): Result<Value, _> = serde_json::from_str(jcs) else {
        panic!("JCS must be valid JSON");
    };

    let Ok(again) = codec_jcs::canonicalize_json(&v) else {
        panic!("canonicalize_json must succeed");
    };

    assert_eq!(
        jcs, again,
        "JCS output is not stable under re-canonicalization"
    );

    assert!(!jcs.contains(' '));
    assert!(!jcs.contains('\n'));
}
