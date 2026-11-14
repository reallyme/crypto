// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe initialized memory immediately before its allocator releases it.

#![cfg(all(feature = "generated", not(target_arch = "wasm32")))]
#![allow(missing_docs, unsafe_code, clippy::unwrap_used)]

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering::Relaxed};
use std::alloc::System;

use buffa::{bytes::Buf, DecodeError, DecodeOptions, Message};
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoAeadSealRequest, CryptoAeadSealRequestOwnedView, CryptoHkdfExtractSha384Request,
    CryptoOperationRequest, CryptoPlatformSignatureSignRequest,
};
use reallyme_crypto_proto::{wire::merge_protobuf, SecretBytes};

struct ObserveRelease;
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static PREFIX: AtomicUsize = AtomicUsize::new(0);
static RESULT: AtomicU8 = AtomicU8::new(0);

// SAFETY: All requests are forwarded to System with their original layouts.
// Only the initialized prefix of the single observed allocation is read,
// while the allocation is still live and exclusively held by deallocation.
unsafe impl GlobalAlloc for ObserveRelease {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if ADDRESS
            .compare_exchange(pointer.addr(), 0, Relaxed, Relaxed)
            .is_ok()
        {
            let length = PREFIX.load(Relaxed).min(layout.size());
            // SAFETY: The observed bytes were initialized before observation,
            // and System has not yet freed the allocation.
            let initialized = unsafe { core::slice::from_raw_parts(pointer, length) };
            RESULT.store(
                if initialized.iter().all(|byte| *byte == 0) {
                    1
                } else {
                    2
                },
                Relaxed,
            );
        }
        // SAFETY: The caller supplies the same pointer and layout as allocation.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: ObserveRelease = ObserveRelease;

fn observe(bytes: &[u8]) {
    assert!(!bytes.is_empty());
    assert_eq!(ADDRESS.load(Relaxed), 0);
    RESULT.store(0, Relaxed);
    PREFIX.store(bytes.len(), Relaxed);
    ADDRESS.store(bytes.as_ptr().addr(), Relaxed);
}

fn wiped() {
    assert_eq!(ADDRESS.load(Relaxed), 0, "old allocation was released");
    assert_eq!(
        RESULT.load(Relaxed),
        1,
        "initialized allocation cleared before release"
    );
}

// One test serializes observation of this integration binary's allocator.
#[test]
fn guarded_replacement_growth_clear_and_drop_wipe_owners() {
    let mut input = vec![0xa5; 64];
    input.truncate(8);
    observe(&input);
    // Include initialized spare capacity, without reading beyond the live slice.
    PREFIX.store(64, Relaxed);
    let mut owner = SecretBytes::from(input);
    owner.extend_from_slice(&[0x16; 128]).unwrap();
    wiped();
    assert_eq!(owner.get(..8), Some([0xa5; 8].as_slice()));
    let clone = owner.clone();
    observe(&owner);
    drop(owner);
    wiped();
    assert_eq!(clone.get(..8), Some([0xa5; 8].as_slice()));
    observe(&clone);
    drop(clone);
    wiped();

    let mut seal = CryptoAeadSealRequest::default().with_key(vec![0xa5; 64]);
    observe(&seal.key);
    seal.merge_from_slice(&[0x12, 1, 9]).unwrap();
    wiped();
    assert_eq!(seal.key, [9]);
    observe(&seal.key);
    Message::clear(&mut seal);
    wiped();

    let mut request = CryptoHkdfExtractSha384Request::default().with_salt(vec![0xa5; 64]);
    observe(request.salt.as_deref().unwrap());
    request = request.with_salt(Vec::new());
    wiped();
    assert_eq!(request.salt.as_deref(), Some([].as_slice()));
    request = request.with_salt(vec![0xa5; 64]);
    observe(request.salt.as_deref().unwrap());
    assert!(merge_protobuf(&mut request, &[0x12, 2, 0xa5]).is_err());
    wiped();

    let mut envelope =
        CryptoOperationRequest::decode_from_slice(&[0x12, 4, 0x12, 2, 0xa5, 0xa5]).unwrap();
    use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_operation_request::Operation;
    if let Some(Operation::AeadSeal(seal)) = &envelope.operation {
        observe(&seal.key);
    }
    envelope.merge_from_slice(&[0x0a, 0]).unwrap();
    wiped();
    assert!(matches!(&envelope.operation, Some(Operation::Hash(_))));

    let message = CryptoAeadSealRequest::default().with_key(vec![0xa5; 64]);
    let view = CryptoAeadSealRequestOwnedView::from_owned(&message).unwrap();
    assert_eq!(view.to_owned_message().unwrap(), message);
    observe(view.bytes());
    drop(view);
    wiped();
}

#[test]
fn fragmented_input_retains_exact_bytes_and_rejects_invalid_utf8() {
    let mut input = (&[0x12, 4, 0xff][..]).chain(&[0, 0xa5, 0x7f][..]);
    let request: CryptoAeadSealRequest = DecodeOptions::new()
        .reject_unknown_fields()
        .decode(&mut input)
        .unwrap();
    assert_eq!(request.key, [0xff, 0, 0xa5, 0x7f]);
    let mut input = (&[0x1a, 3, b'a'][..]).chain(&[b'b', 0xff][..]);
    assert!(matches!(
        DecodeOptions::new()
            .reject_unknown_fields()
            .decode::<CryptoPlatformSignatureSignRequest>(&mut input),
        Err(DecodeError::InvalidUtf8)
    ));
}
