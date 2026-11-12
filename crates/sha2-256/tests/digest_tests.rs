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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn digest_length_is_stable() {
    let output = digest(b"hello");
    assert_eq!(output.as_bytes().len(), SHA2_256_DIGEST_LENGTH);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn digest_is_deterministic() {
    let first = digest(b"same input");
    let second = digest(b"same input");
    assert_eq!(first, second);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn digest_changes_when_message_changes() {
    let first = digest(b"message-one");
    let second = digest(b"message-two");
    assert_ne!(first, second);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn known_vectors_match() {
    for vector in vectors::all_vectors() {
        let output = digest(vector.message);
        assert_eq!(hex::encode(output.as_bytes()), vector.digest_hex);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn digest_owner_and_hash_state_keep_drop_cleanup() {
    fn requires_cleanup<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    requires_cleanup::<crypto_sha2_256::Sha2_256Digest>();
    requires_cleanup::<sha2::Sha256>();
    requires_cleanup::<zeroize::Zeroizing<[u32; 8]>>();
    requires_cleanup::<
        zeroize::Zeroizing<sha2::digest::block_api::Buffer<sha2::block_api::Sha256VarCore>>,
    >();
    requires_cleanup::<zeroize::Zeroizing<[u8; 4]>>();
    let mut output = digest(b"sensitive digest input");
    let exported = output.clone().into_bytes();
    assert_eq!(output.as_bytes(), &exported);
    output.zeroize();
    assert_eq!(output.as_bytes(), &[0; SHA2_256_DIGEST_LENGTH]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn block_and_padding_boundaries_preserve_existing_outputs() {
    use sha2::Digest;
    for length in (0..=1024).chain([4095, 4096, 4097, 65535, 65536, 65537]) {
        let input: Vec<u8> = (0_u8..=255).cycle().take(length).collect();
        assert_eq!(
            digest(&input).as_bytes().as_slice(),
            sha2::Sha256::digest(&input).as_slice()
        );
    }
}
