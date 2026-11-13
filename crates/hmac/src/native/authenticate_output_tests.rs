// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::FinalizedTagBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn finalized_tag_storage_has_a_clearing_owner() {
    fn require_clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    require_clearing::<FinalizedTagBytes<[u8; 32]>>();
    require_clearing::<FinalizedTagBytes<[u8; 48]>>();
    require_clearing::<FinalizedTagBytes<[u8; 64]>>();
    let mut output = FinalizedTagBytes([0xa5; 64]);
    output.zeroize();
    assert_eq!(output.0, [0; 64]);
}
