// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use crypto_sha3_256::{digest, Sha3_256Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn returned_digest_owners_clear_independently_without_released_memory_reads() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<Sha3_256Digest>();
    let mut original = digest(b"independent digest owner");
    let mut retained = original.clone();
    assert_eq!(original, retained);
    assert_ne!(original.as_bytes().as_ptr(), retained.as_bytes().as_ptr());
    original.zeroize();
    assert!(original.as_bytes().iter().all(|byte| *byte == 0));
    assert_eq!(retained, digest(b"independent digest owner"));
    retained.zeroize();
    assert!(retained.as_bytes().iter().all(|byte| *byte == 0));
}
