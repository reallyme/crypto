// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use crypto_sha3::{
    digest_sha3_224, digest_sha3_384, digest_sha3_512, SHA3_224_DIGEST_LENGTH,
    SHA3_384_DIGEST_LENGTH, SHA3_512_DIGEST_LENGTH,
};

#[test]
fn digest_lengths_are_stable() {
    assert_eq!(
        digest_sha3_224(b"hello").as_bytes().len(),
        SHA3_224_DIGEST_LENGTH
    );
    assert_eq!(
        digest_sha3_384(b"hello").as_bytes().len(),
        SHA3_384_DIGEST_LENGTH
    );
    assert_eq!(
        digest_sha3_512(b"hello").as_bytes().len(),
        SHA3_512_DIGEST_LENGTH
    );
}

#[test]
fn digests_are_deterministic() {
    assert_eq!(
        digest_sha3_224(b"same input"),
        digest_sha3_224(b"same input")
    );
    assert_eq!(
        digest_sha3_384(b"same input"),
        digest_sha3_384(b"same input")
    );
    assert_eq!(
        digest_sha3_512(b"same input"),
        digest_sha3_512(b"same input")
    );
}

#[test]
fn digests_change_when_message_changes() {
    assert_ne!(
        digest_sha3_224(b"message-one"),
        digest_sha3_224(b"message-two")
    );
    assert_ne!(
        digest_sha3_384(b"message-one"),
        digest_sha3_384(b"message-two")
    );
    assert_ne!(
        digest_sha3_512(b"message-one"),
        digest_sha3_512(b"message-two")
    );
}

#[test]
fn known_vectors_match() {
    let sha3_224_empty = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
    let sha3_224_abc = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf";
    let sha3_384_empty = concat!(
        "0c63a75b845e4f7d01107d852e4c2485",
        "c51a50aaaa94fc61995e71bbee983a2a",
        "c3713831264adb47fb6bd1e058d5f004"
    );
    let sha3_384_abc = concat!(
        "ec01498288516fc926459f58e2c6ad8d",
        "f9b473cb0fc08c2596da7cf0e49be4b2",
        "98d88cea927ac7f539f1edf228376d25"
    );
    let sha3_512_empty = concat!(
        "a69f73cca23a9ac5c8b567dc185a756e",
        "97c982164fe25859e0d1dcc1475c80a6",
        "15b2123af1f5f94c11e3e9402c3ac558",
        "f500199d95b6d3e301758586281dcd26"
    );
    let sha3_512_abc = concat!(
        "b751850b1a57168a5693cd924b6b096e",
        "08f621827444f70d884f5d0240d2712e",
        "10e116e9192af3c91a7ec57647e39340",
        "57340b4cf408d5a56592f8274eec53f0"
    );

    assert_eq!(hex::encode(digest_sha3_224(b"").as_bytes()), sha3_224_empty);
    assert_eq!(
        hex::encode(digest_sha3_224(b"abc").as_bytes()),
        sha3_224_abc
    );
    assert_eq!(hex::encode(digest_sha3_384(b"").as_bytes()), sha3_384_empty);
    assert_eq!(
        hex::encode(digest_sha3_384(b"abc").as_bytes()),
        sha3_384_abc
    );
    assert_eq!(hex::encode(digest_sha3_512(b"").as_bytes()), sha3_512_empty);
    assert_eq!(
        hex::encode(digest_sha3_512(b"abc").as_bytes()),
        sha3_512_abc
    );
}
