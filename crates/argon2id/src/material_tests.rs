// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::Argon2idDerivedKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn final_output_owner_is_zeroed_and_clears_its_initialized_storage() {
    fn require_cleanup<T: ZeroizeOnDrop>() {}
    require_cleanup::<Argon2idDerivedKey>();
    let mut output = Argon2idDerivedKey::zeroed();
    assert!(output.as_bytes().iter().all(|byte| *byte == 0));
    output.as_mut_slice().fill(0xa5);
    assert!(output.as_bytes().iter().all(|byte| *byte == 0xa5));
    output.zeroize();
    assert!(output.as_bytes().iter().all(|byte| *byte == 0));
}
