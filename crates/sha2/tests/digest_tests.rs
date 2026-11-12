// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use crypto_sha2::{
    digest_sha2_384, digest_sha2_512, SHA2_384_DIGEST_LENGTH, SHA2_512_DIGEST_LENGTH,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn digest_owners_and_hash_states_keep_drop_cleanup() {
    fn requires_cleanup<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    requires_cleanup::<crypto_sha2::Sha2_384Digest>();
    requires_cleanup::<crypto_sha2::Sha2_512Digest>();
    requires_cleanup::<sha2::Sha384>();
    requires_cleanup::<sha2::Sha512>();
    requires_cleanup::<zeroize::Zeroizing<[u64; 8]>>();
    requires_cleanup::<
        zeroize::Zeroizing<sha2::digest::block_api::Buffer<sha2::block_api::Sha512VarCore>>,
    >();
    requires_cleanup::<zeroize::Zeroizing<[u8; 8]>>();
    let mut sha384 = digest_sha2_384(b"sensitive digest input");
    let mut sha512 = digest_sha2_512(b"sensitive digest input");
    assert_eq!(sha384.as_bytes(), &sha384.clone().into_bytes());
    assert_eq!(sha512.as_bytes(), &sha512.clone().into_bytes());
    sha384.zeroize();
    sha512.zeroize();
    assert_eq!(sha384.as_bytes(), &[0; SHA2_384_DIGEST_LENGTH]);
    assert_eq!(sha512.as_bytes(), &[0; SHA2_512_DIGEST_LENGTH]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn block_and_padding_boundaries_preserve_existing_outputs() {
    use sha2::Digest;
    for length in (0..=1024).chain([4095, 4096, 4097, 65535, 65536, 65537]) {
        let input: Vec<u8> = (0_u8..=255).cycle().take(length).collect();
        assert_eq!(
            digest_sha2_384(&input).as_bytes().as_slice(),
            sha2::Sha384::digest(&input).as_slice()
        );
        assert_eq!(
            digest_sha2_512(&input).as_bytes().as_slice(),
            sha2::Sha512::digest(&input).as_slice()
        );
    }
}
