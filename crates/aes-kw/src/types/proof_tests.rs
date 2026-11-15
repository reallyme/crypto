// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{validate_plaintext_len, validate_wrapped_len};
use crate::AES_KW_MAX_KEY_DATA_LENGTH;
use crypto_core::CryptoError;

#[kani::proof]
fn aes_kw_length_checks_match_semiblock_constraints() {
    const SEMIBLOCK_BYTES: usize = 8;
    const MIN_PLAINTEXT_BYTES: usize = 2 * SEMIBLOCK_BYTES;

    let len: usize = kani::any();
    let plain = validate_plaintext_len(len);
    let wrapped = validate_wrapped_len(len);
    let valid_plain = |bytes| {
        (MIN_PLAINTEXT_BYTES..=AES_KW_MAX_KEY_DATA_LENGTH).contains(&bytes)
            && bytes % SEMIBLOCK_BYTES == 0
    };
    let valid_wrapped = len.checked_sub(SEMIBLOCK_BYTES).is_some_and(valid_plain);
    let length_error = Err(CryptoError::PRIMITIVE_INVALID_LENGTH);

    assert_eq!(
        plain,
        if valid_plain(len) {
            Ok(())
        } else {
            length_error
        }
    );
    assert_eq!(wrapped, if valid_wrapped { Ok(()) } else { length_error });
    kani::cover!(
        len == usize::MAX && wrapped.is_err(),
        "reject overflow-sized input"
    );
    kani::cover!(
        len == MIN_PLAINTEXT_BYTES + SEMIBLOCK_BYTES && wrapped.is_ok(),
        "accept two wrapped data semiblocks"
    );
}
