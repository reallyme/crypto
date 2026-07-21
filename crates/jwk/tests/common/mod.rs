// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::panic)]

use serde_json::Value;

pub fn assert_jcs(jcs: &str) {
    let Ok(v): Result<Value, _> = serde_json::from_str(jcs) else {
        panic!("JCS must be valid JSON");
    };

    let Ok(again) = codec_jcs::canonicalize_trusted_json_value(&v) else {
        panic!("canonicalize_trusted_json_value must succeed");
    };

    assert_eq!(
        jcs, again,
        "JCS output is not stable under re-canonicalization"
    );

    assert!(!jcs.contains(' '));
    assert!(!jcs.contains('\n'));
}
