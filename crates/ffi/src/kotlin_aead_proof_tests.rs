// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{publish_open_result, KOTLIN_NATIVE_BACKEND_INTERNAL, KOTLIN_NATIVE_OK};
use crate::kotlin_result::KOTLIN_NATIVE_AUTHENTICATION_FAILED;
use crate::status::{CRYPTO_AUTHENTICATION_FAILED, CRYPTO_OK};

#[kani::proof]
#[kani::unwind(6)]
fn jni_open_publishes_no_payload_on_authentication_failure() {
    let output: [u8; 4] = kani::any();
    let produced_len: usize = kani::any();
    let authenticated: bool = kani::any();
    let status = if authenticated {
        CRYPTO_OK
    } else {
        CRYPTO_AUTHENTICATION_FAILED
    };
    let mut published = false;
    publish_open_result(status, produced_len, &output, |status, payload| {
        published = true;
        if !authenticated {
            assert_eq!(status, KOTLIN_NATIVE_AUTHENTICATION_FAILED);
            assert!(payload.is_empty());
        } else if produced_len == output.len() {
            assert_eq!(status, KOTLIN_NATIVE_OK);
            assert_eq!(payload, output);
        } else {
            assert_eq!(status, KOTLIN_NATIVE_BACKEND_INTERNAL);
            assert!(payload.is_empty());
        }
        kani::cover!(!authenticated && produced_len == output.len() && output != [0; 4]);
        kani::cover!(authenticated && produced_len == output.len());
    });
    assert!(published);
}
