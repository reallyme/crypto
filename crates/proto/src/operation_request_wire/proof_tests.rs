// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{classify_json_operation, enforce_json_operation_policy, malformed_json_error};
use super::{secret_json_operation_error, JsonOperationPolicy};

const MAX_MODELED_SELECTOR_BYTES: usize = 64;
const MAX_MODELED_REQUEST_BYTES: usize = 12;
const MAX_MODELED_SECRET_SUFFIX_BYTES: usize = 16;
const MAX_MODELED_STRING_BYTES: usize = 8;

#[kani::proof]
#[kani::unwind(65)]
fn only_reviewed_selectors_are_admitted() {
    let storage: [u8; MAX_MODELED_SELECTOR_BYTES] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= storage.len());
    let selector = &storage[..length];

    // This is the reviewed allowlist from the operation wire contract.
    // Every other selector must take a path that prevents JSON decoding.
    let allowed: &[&[u8]] = &[
        b"hash",
        b"signatureGenerateKeyPair",
        b"signatureVerify",
        b"rsaVerify",
        b"kemGenerateKeyPair",
        b"kemEncapsulate",
        b"hpkeGenerateKeyPair",
        b"hpkeSenderExport",
    ];
    assert_eq!(
        classify_json_operation(selector) == Some(JsonOperationPolicy::Allowed),
        allowed.contains(&selector),
    );
}

#[kani::proof]
#[kani::unwind(28)]
fn secret_selector_is_rejected_regardless_of_the_following_bytes() {
    // The transport tests enumerate the remaining schema selectors. Here the
    // bytes after the closing quote are unconstrained, including the colon.
    const PREFIX: &[u8; 11] = br#"{"aeadSeal""#;
    const STORAGE_LEN: usize = PREFIX.len() + MAX_MODELED_SECRET_SUFFIX_BYTES;
    let mut bytes: [u8; STORAGE_LEN] = kani::any();
    bytes[..PREFIX.len()].copy_from_slice(PREFIX);
    let length: usize = kani::any();
    kani::assume((PREFIX.len()..=bytes.len()).contains(&length));

    assert_eq!(
        enforce_json_operation_policy(&bytes[..length]),
        Err(secret_json_operation_error()),
    );
}

#[kani::proof]
#[kani::unwind(40)]
fn comma_inside_a_string_cannot_hide_a_second_top_level_member() {
    const PREFIX: &[u8] = br#"{"hash":{"message":""#;
    const SINGLE_MEMBER_SUFFIX: &[u8] = br#""}}"#;
    const SECOND_MEMBER_SUFFIX: &[u8] = br#""},"aeadOpen":{}}"#;
    const STRING_END: usize = PREFIX.len() + MAX_MODELED_STRING_BYTES;
    const SINGLE_MEMBER_LEN: usize = STRING_END + SINGLE_MEMBER_SUFFIX.len();

    let content: [u8; MAX_MODELED_STRING_BYTES] = kani::any();
    // Unescaped string bytes may include commas, braces and brackets. The
    // scanner must ignore these bytes until it reaches the closing quote.
    for byte in content {
        kani::assume(byte >= b' ' && byte != b'"' && byte != b'\\');
    }

    let mut request = [0_u8; STRING_END + SECOND_MEMBER_SUFFIX.len()];
    let (prefix, body) = request.split_at_mut(PREFIX.len());
    let (string, tail) = body.split_at_mut(content.len());
    prefix.copy_from_slice(PREFIX);
    string.copy_from_slice(&content);
    tail[..SINGLE_MEMBER_SUFFIX.len()].copy_from_slice(SINGLE_MEMBER_SUFFIX);
    assert_eq!(
        enforce_json_operation_policy(&request[..SINGLE_MEMBER_LEN]),
        Ok(())
    );

    request[STRING_END..].copy_from_slice(SECOND_MEMBER_SUFFIX);
    assert_eq!(
        enforce_json_operation_policy(&request),
        Err(malformed_json_error()),
    );
}

#[kani::proof]
#[kani::unwind(13)]
fn short_arbitrary_requests_are_scanned_without_panics() {
    let bytes: [u8; MAX_MODELED_REQUEST_BYTES] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= bytes.len());
    let _ = enforce_json_operation_policy(&bytes[..length]);
}
