// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
use crypto_sha2_256::{digest, SHA2_256_DIGEST_LENGTH};
use zeroize::{Zeroize, ZeroizeOnDrop};

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

#[test]
fn digest_owner_and_hash_state_keep_drop_cleanup() {
    fn requires_cleanup<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    requires_cleanup::<crypto_sha2_256::Sha2_256Digest>();
    requires_cleanup::<sha2::Sha256>();
    let mut output = digest(b"sensitive digest input");
    let exported = output.clone().into_bytes();
    assert_eq!(output.as_bytes(), &exported);
    output.zeroize();
    assert_eq!(output.as_bytes(), &[0; SHA2_256_DIGEST_LENGTH]);
}

#[test]
fn block_and_padding_boundaries_preserve_existing_outputs() {
    use sha2::Digest;
    for length in [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1024] {
        let input = vec![0xa5; length];
        assert_eq!(
            digest(&input).as_bytes().as_slice(),
            sha2::Sha256::digest(&input).as_slice()
        );
    }
}
