// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
use crypto_sha2_256::{digest, SHA2_256_DIGEST_LENGTH};

mod vectors;

#[test]
fn digest_length_is_stable() {
    let output = digest(b"hello");
    assert_eq!(output.as_bytes().len(), SHA2_256_DIGEST_LENGTH);
}

#[test]
fn digest_is_deterministic() {
    let first = digest(b"same input");
    let second = digest(b"same input");
    assert_eq!(first, second);
}

#[test]
fn digest_changes_when_message_changes() {
    let first = digest(b"message-one");
    let second = digest(b"message-two");
    assert_ne!(first, second);
}

#[test]
fn known_vectors_match() {
    for vector in vectors::all_vectors() {
        let output = digest(vector.message);
        assert_eq!(hex::encode(output.as_bytes()), vector.digest_hex);
    }
}
