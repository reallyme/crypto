// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use crypto_sha2::{
    digest_sha2_384, digest_sha2_512, SHA2_384_DIGEST_LENGTH, SHA2_512_DIGEST_LENGTH,
};

#[test]
fn digest_lengths_are_stable() {
    assert_eq!(
        digest_sha2_384(b"hello").as_bytes().len(),
        SHA2_384_DIGEST_LENGTH
    );
    assert_eq!(
        digest_sha2_512(b"hello").as_bytes().len(),
        SHA2_512_DIGEST_LENGTH
    );
}

#[test]
fn digests_are_deterministic() {
    assert_eq!(
        digest_sha2_384(b"same input"),
        digest_sha2_384(b"same input")
    );
    assert_eq!(
        digest_sha2_512(b"same input"),
        digest_sha2_512(b"same input")
    );
}

#[test]
fn digests_change_when_message_changes() {
    assert_ne!(
        digest_sha2_384(b"message-one"),
        digest_sha2_384(b"message-two")
    );
    assert_ne!(
        digest_sha2_512(b"message-one"),
        digest_sha2_512(b"message-two")
    );
}

#[test]
fn known_vectors_match() {
    let sha384_empty = concat!(
        "38b060a751ac96384cd9327eb1b1e36a",
        "21fdb71114be07434c0cc7bf63f6e1da",
        "274edebfe76f65fbd51ad2f14898b95b"
    );
    let sha384_abc = concat!(
        "cb00753f45a35e8bb5a03d699ac65007",
        "272c32ab0eded1631a8b605a43ff5bed",
        "8086072ba1e7cc2358baeca134c825a7"
    );
    let sha512_empty = concat!(
        "cf83e1357eefb8bdf1542850d66d8007",
        "d620e4050b5715dc83f4a921d36ce9ce",
        "47d0d13c5d85f2b0ff8318d2877eec2f",
        "63b931bd47417a81a538327af927da3e"
    );
    let sha512_abc = concat!(
        "ddaf35a193617abacc417349ae204131",
        "12e6fa4e89a97ea20a9eeee64b55d39a",
        "2192992a274fc1a836ba3c23a3feebbd",
        "454d4423643ce80e2a9ac94fa54ca49f"
    );

    assert_eq!(hex::encode(digest_sha2_384(b"").as_bytes()), sha384_empty);
    assert_eq!(hex::encode(digest_sha2_384(b"abc").as_bytes()), sha384_abc);
    assert_eq!(hex::encode(digest_sha2_512(b"").as_bytes()), sha512_empty);
    assert_eq!(hex::encode(digest_sha2_512(b"abc").as_bytes()), sha512_abc);
}
