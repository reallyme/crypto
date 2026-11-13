// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[test]
fn existing_narrow_features_provide_clearing_ownership_for_exact_mlkem_coins_type() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<Zeroizing<ml_kem::B32>>();
    let mut coins = Zeroizing::new(ml_kem::B32::default());
    coins.as_mut_slice().fill(0x5a);
    coins.zeroize();
    assert!(coins.as_slice().iter().all(|byte| *byte == 0));
}
