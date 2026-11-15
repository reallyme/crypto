// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::unwrap_with;
use aes_kw::Error as AesKwError;
use crypto_core::CryptoError;
use zeroize::ZeroizeOnDrop;

fn require_zeroizing_owner<T: ZeroizeOnDrop>(_: &T) {}

#[kani::proof]
#[kani::unwind(32)]
fn aes_kw_does_not_release_failed_unwrap_writes() {
    const KEY_BYTES: usize = 16;
    let wrapped: [u8; KEY_BYTES + 8] = kani::any();
    let candidate: [u8; KEY_BYTES] = kani::any();
    let written: [bool; KEY_BYTES] = kani::any();
    let backend_result = if kani::any() {
        Ok(())
    } else if kani::any() {
        Err(AesKwError::IntegrityCheckFailed)
    } else if kani::any() {
        Err(AesKwError::InvalidDataSize)
    } else {
        Err(AesKwError::InvalidOutputSize {
            expected_len: kani::any(),
        })
    };

    let mut staging = None;
    let result = unwrap_with(&wrapped, |output| {
        assert_eq!(output, &[0; KEY_BYTES]);
        staging = Some(output.as_ptr());
        for (index, should_write) in written.into_iter().enumerate() {
            if should_write {
                output[index] = candidate[index];
            }
        }
        backend_result
    });

    match backend_result {
        Ok(()) => {
            let owner = result.expect("success must return a zeroizing key owner");
            require_zeroizing_owner(&owner);
            assert_eq!(Some(owner.as_bytes().as_ptr()), staging);
            assert_eq!(owner.len(), KEY_BYTES);
            for (index, should_write) in written.into_iter().enumerate() {
                assert_eq!(
                    owner.as_bytes()[index],
                    if should_write { candidate[index] } else { 0 }
                );
            }
        }
        Err(AesKwError::IntegrityCheckFailed) => {
            assert_eq!(
                result.err(),
                Some(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
            );
        }
        Err(_) => {
            assert_eq!(result.err(), Some(CryptoError::BACKEND_INTERNAL));
        }
    }
    kani::cover!(
        backend_result == Err(AesKwError::IntegrityCheckFailed) && written == [true; KEY_BYTES],
        "integrity failure after a complete write"
    );
    kani::cover!(
        backend_result == Err(AesKwError::IntegrityCheckFailed) && written[0] && !written[1],
        "integrity failure after a partial write"
    );
}

#[kani::proof]
fn aes_kw_rejects_short_and_unaligned_input_before_backend() {
    const MIN_WRAPPED_BYTES: usize = 24;
    let wrapped: [u8; MIN_WRAPPED_BYTES + 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= wrapped.len());
    kani::assume(len < MIN_WRAPPED_BYTES || len % 8 != 0);

    let result = unwrap_with(&wrapped[..len], |_| {
        kani::assert(false, "malformed key data must never reach unwrap");
        Ok(())
    });
    assert_eq!(result.err(), Some(CryptoError::PRIMITIVE_INVALID_LENGTH));
}
