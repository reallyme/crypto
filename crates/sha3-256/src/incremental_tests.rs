// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{Sha3_256Hasher, SHA3_256_MAX_INPUT_BYTES};
use crate::{digest, CryptoError};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn every_chunk_boundary_matches_one_shot_and_standard_vectors() {
    for input in [
        b"".as_slice(),
        b"abc",
        b"The quick brown fox jumps over the lazy dog",
    ] {
        for split in 0..=input.len() {
            let mut context = Sha3_256Hasher::new();
            context.update(&input[..split]).unwrap();
            context.update(&[]).unwrap();
            context.update(&input[split..]).unwrap();
            assert_eq!(
                context.processed_bytes(),
                u64::try_from(input.len()).unwrap()
            );
            assert_eq!(context.finalize().unwrap(), digest(input));
        }
    }
    let input: Vec<u8> = (0_u8..=255).cycle().take(65537).collect();
    for length in [
        0, 1, 55, 56, 63, 64, 65, 135, 136, 137, 255, 256, 4096, 65537,
    ] {
        for chunk_size in [1, 7, 63, 64, 65, 135, 136, 137, 1024] {
            let mut context = Sha3_256Hasher::default();
            for chunk in input[..length].chunks(chunk_size) {
                context.update(chunk).unwrap();
            }
            assert_eq!(context.finalize().unwrap(), digest(&input[..length]));
        }
    }
}

#[test]
fn cleanup_invalidates_the_context_and_returns_schema_reasons() {
    fn cleanup_owner<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    cleanup_owner::<Sha3_256Hasher>();
    let mut context = Sha3_256Hasher::new();
    context.update(b"private transcript").unwrap();
    context.zeroize();
    assert_eq!(context.processed_bytes(), 0);
    assert_eq!(
        context.update(b"later"),
        Err(CryptoError::BACKEND_INVALID_STATE)
    );
    assert_eq!(context.update(&[]), Err(CryptoError::BACKEND_INVALID_STATE));
    assert_eq!(context.finalize(), Err(CryptoError::BACKEND_INVALID_STATE));
}

#[test]
fn limit_rejection_does_not_absorb_any_rejected_bytes() {
    let mut context = Sha3_256Hasher::new();
    context.update(b"prefix").unwrap();
    // Exercise the arithmetic boundary without manufacturing an enormous input
    // or importing attacker-controlled hash state through the public API.
    context.processed_bytes = SHA3_256_MAX_INPUT_BYTES.checked_sub(1).unwrap();
    context.update(b"x").unwrap();
    assert_eq!(context.processed_bytes(), SHA3_256_MAX_INPUT_BYTES);
    use sha3::digest::common::hazmat::SerializableState;
    let state = context.state.as_ref().unwrap().serialize();
    assert_eq!(
        context.update(b"rejected"),
        Err(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    assert_eq!(context.processed_bytes(), SHA3_256_MAX_INPUT_BYTES);
    assert_eq!(context.state.as_ref().unwrap().serialize(), state);
    context.update(&[]).unwrap();
}

#[test]
fn explicit_cleanup_drops_the_backend_owner() {
    let mut context = Sha3_256Hasher::new();
    context.update(&[0x5a; 149]).unwrap();
    context.zeroize();
    assert!(context.state.is_none());
}
