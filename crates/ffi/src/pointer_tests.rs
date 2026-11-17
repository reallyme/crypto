// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for C ABI pointer and length validation helpers.

#![allow(unsafe_code)]

use super::{begin_input_range_call, validate_read_pair, validate_write_pair};
use crate::guard::ffi_guard;
use crate::pointer::{
    read_slice, validate_disjoint_input_len_pair, validate_disjoint_input_output_pair,
    validate_disjoint_len_outputs, validate_disjoint_output_pair, validate_len_output,
    validate_output_len_pair, write_fixed, write_fixed_pair, write_i32, write_len, write_slice,
};
use crate::sha2_256::{rm_crypto_sha2_256_digest, SHA2_256_DIGEST_LEN};
use crate::status::{
    CryptoStatus, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT,
    CRYPTO_OK,
};
use core::ptr::NonNull;

/// Track input/output aliasing for a standalone Rust use of the pointer helpers.
///
/// Non-empty foreign-memory access fails closed without an active scope. C
/// exports establish the same scope through [`crate::guard::ffi_guard`]; Rust
/// callers can use this function independently of the panic firewall. Nested
/// scopes are rejected, and range metadata is cleared on return or unwinding.
/// References obtained from unsafe helpers must not escape the closure.
fn with_pointer_ranges(operation: impl FnOnce() -> CryptoStatus) -> CryptoStatus {
    let _ranges = match begin_input_range_call() {
        Ok(guard) => guard,
        Err(status) => return status,
    };
    operation()
}

#[test]
fn read_slice_accepts_null_only_for_empty_input() {
    // SAFETY: An empty input performs no access, so its pointer may be null.
    let empty = unsafe { read_slice(core::ptr::null(), 0) };
    assert!(matches!(empty, Ok(value) if value.is_empty()));

    // SAFETY: Null nonempty input is rejected before constructing a reference.
    let status = unsafe { read_slice(core::ptr::null(), 1) };
    assert_eq!(status, Err(CRYPTO_INVALID_ARGUMENT));
}

#[test]
fn read_slice_rejects_lengths_that_cannot_be_valid_rust_slices() {
    let ptr = NonNull::<u8>::dangling().as_ptr();
    // SAFETY: An oversized slice is rejected before the dangling address is read.
    let status = unsafe { read_slice(ptr, usize::MAX) };
    assert_eq!(status, Err(CRYPTO_INVALID_ARGUMENT));
}

#[test]
fn write_slice_accepts_null_only_for_empty_output() {
    // SAFETY: An empty output performs no access, so its pointer may be null.
    let empty = unsafe { write_slice(core::ptr::null_mut(), 0) };
    assert!(matches!(empty, Ok(value) if value.is_empty()));

    // SAFETY: Null nonempty output is rejected before constructing a reference.
    let status = unsafe { write_slice(core::ptr::null_mut(), 1) };
    assert_eq!(status, Err(CRYPTO_INVALID_ARGUMENT));
}

#[test]
fn write_slice_rejects_lengths_that_cannot_be_valid_rust_slices() {
    let ptr = NonNull::<u8>::dangling().as_ptr();
    // SAFETY: An oversized slice is rejected before the dangling address is used.
    let status = unsafe { write_slice(ptr, usize::MAX) };
    assert_eq!(status, Err(CRYPTO_INVALID_ARGUMENT));
}

#[test]
fn slice_helpers_reject_address_wraparound_before_constructing_references() {
    let ptr = core::ptr::without_provenance_mut::<u8>(usize::MAX);
    // SAFETY: These deliberately invalid ranges must be rejected before a
    // reference is constructed or memory is accessed, including outside a guard.
    assert_eq!(unsafe { read_slice(ptr, 2) }, Err(CRYPTO_INVALID_ARGUMENT));
    // SAFETY: The overflowing address range is rejected before memory access.
    assert_eq!(unsafe { write_slice(ptr, 2) }, Err(CRYPTO_INVALID_ARGUMENT));
    // SAFETY: The overflowing address range is rejected before memory access.
    assert_eq!(unsafe { write_fixed(ptr, 2, &[]) }, CRYPTO_INVALID_ARGUMENT);
}

#[test]
fn write_fixed_rejects_small_buffers_without_mutating_them() {
    let mut output = [0xA5_u8; 2];
    // SAFETY: The live output covers its declared length; the source is separate.
    let status = unsafe { write_fixed(output.as_mut_ptr(), output.len(), &[1, 2, 3]) };
    assert_eq!(status, CRYPTO_BUFFER_TOO_SMALL);
    assert_eq!(output, [0xA5, 0xA5]);
}

#[test]
fn write_fixed_rejects_overlapping_input_and_output_ranges() {
    let mut storage = [1_u8, 2, 3, 4, 0xA5, 0xA5, 0xA5, 0xA5];
    // Derive both addresses from one borrow so creating the output pointer
    // does not invalidate the provenance used to construct the input slice.
    let pointer = storage.as_mut_ptr();
    let input_ptr = pointer.cast_const();
    let output_ptr = pointer.wrapping_add(2);
    // SAFETY: The first four initialized bytes stay alive until the input is
    // no longer used. The writer must reject overlap without creating a mutable
    // reference or mutating the allocation.
    let input = unsafe { core::slice::from_raw_parts(input_ptr, 4) };

    // SAFETY: Both ranges lie in the live allocation; overlap must be rejected.
    let status = unsafe { write_fixed(output_ptr, 4, input) };

    assert_eq!(status, CRYPTO_INVALID_ARGUMENT);
    assert_eq!(storage, [1, 2, 3, 4, 0xA5, 0xA5, 0xA5, 0xA5]);
}

#[test]
fn nested_ffi_guard_fails_without_clearing_outer_input_ranges() {
    let mut storage = [0xA5_u8; 64];
    let mut digest = [0_u8; SHA2_256_DIGEST_LEN];

    let status = ffi_guard(|| {
        // SAFETY: The input is initialized and immutable during the guarded call.
        let registered_len = match unsafe { read_slice(storage.as_ptr(), 32) } {
            Ok(value) => value.len(),
            Err(status) => return status,
        };
        if registered_len != 32 {
            return CRYPTO_INVALID_ARGUMENT;
        }

        // SAFETY: Input and output are live, correctly sized, and disjoint.
        let nested_status = unsafe {
            rm_crypto_sha2_256_digest(storage.as_ptr(), 32, digest.as_mut_ptr(), digest.len())
        };
        if nested_status != CRYPTO_INTERNAL_ERROR {
            return CRYPTO_INTERNAL_ERROR;
        }

        // SAFETY: The live output overlaps a registered input and must be
        // rejected before any mutable reference or write is created.
        let overlap_status = unsafe { write_fixed(storage.as_mut_ptr(), storage.len(), &[1]) };
        if overlap_status != CRYPTO_INVALID_ARGUMENT {
            return CRYPTO_INTERNAL_ERROR;
        }
        CRYPTO_OK
    });

    assert_eq!(status, CRYPTO_OK);
}

#[test]
fn input_output_helpers_reject_partial_overlap() {
    let mut storage = [0_u8; 32];
    let input = storage.as_ptr();
    let output = storage.as_mut_ptr().wrapping_add(8);

    assert_eq!(
        validate_disjoint_input_output_pair(input, 16, output, 16),
        CRYPTO_INVALID_ARGUMENT
    );

    let len_out = storage.as_mut_ptr().cast::<usize>();
    assert_eq!(
        validate_disjoint_input_len_pair(input, storage.len(), len_out),
        CRYPTO_INVALID_ARGUMENT
    );
}

#[test]
fn output_pair_helpers_reject_overlaps_without_writing() {
    let mut storage = [0_u8; 32];
    let first = storage.as_mut_ptr();
    let second = storage.as_mut_ptr().wrapping_add(8);

    assert_eq!(
        validate_disjoint_output_pair(first, 16, second, 16),
        CRYPTO_INVALID_ARGUMENT
    );

    let len_out = storage.as_mut_ptr().wrapping_add(4).cast::<usize>();
    assert_eq!(
        validate_output_len_pair(first, 16, len_out),
        CRYPTO_INVALID_ARGUMENT
    );

    let first_len = storage.as_mut_ptr().cast::<usize>();
    let second_len = storage.as_mut_ptr().wrapping_add(1).cast::<usize>();
    assert_eq!(
        validate_disjoint_len_outputs(first_len, second_len),
        CRYPTO_INVALID_ARGUMENT
    );
}

#[test]
fn output_registry_rejects_byte_buffer_aliasing_a_length_pointer() {
    let mut first_output = [0xA5_u8; 16];
    let mut shared = usize::MAX;
    let mut second_length = usize::MAX;
    let shared_ptr = &mut shared as *mut usize;

    let status = ffi_guard(|| {
        let first_status =
            validate_output_len_pair(first_output.as_mut_ptr(), first_output.len(), shared_ptr);
        if first_status != CRYPTO_OK {
            return first_status;
        }
        validate_output_len_pair(
            shared_ptr.cast::<u8>(),
            core::mem::size_of::<usize>(),
            &mut second_length,
        )
    });

    assert_eq!(status, CRYPTO_INVALID_ARGUMENT);
    assert_eq!(first_output, [0xA5_u8; 16]);
    assert_eq!(shared, usize::MAX);
    assert_eq!(second_length, usize::MAX);
}

#[test]
fn typed_output_writes_reject_null_and_misaligned_pointers() {
    assert_eq!(
        // SAFETY: Null output slots are rejected before any write.
        unsafe { write_len(core::ptr::null_mut(), 1) },
        CRYPTO_INVALID_ARGUMENT
    );
    assert_eq!(
        validate_len_output(core::ptr::null_mut()),
        CRYPTO_INVALID_ARGUMENT
    );
    assert_eq!(
        // SAFETY: Null output slots are rejected before any write.
        unsafe { write_i32(core::ptr::null_mut(), 1) },
        CRYPTO_INVALID_ARGUMENT
    );

    let mut usize_storage = [0_usize; 2];
    let misaligned_usize = usize_storage
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<usize>();
    assert_eq!(
        // SAFETY: The deliberately misaligned slot is rejected before any write.
        unsafe { write_len(misaligned_usize, 1) },
        CRYPTO_INVALID_ARGUMENT
    );

    let mut i32_storage = [0_i32; 2];
    let misaligned_i32 = i32_storage
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<i32>();
    assert_eq!(
        // SAFETY: The deliberately misaligned slot is rejected before any write.
        unsafe { write_i32(misaligned_i32, 1) },
        CRYPTO_INVALID_ARGUMENT
    );
}

#[test]
fn typed_output_writes_accept_aligned_pointers() {
    let mut len_out = 0_usize;
    let mut flag_out = 0_i32;

    assert_eq!(
        with_pointer_ranges(|| {
            // SAFETY: The aligned slot is exclusively writable through the scope.
            unsafe { write_len(&mut len_out, 7) }
        }),
        CRYPTO_OK
    );
    assert_eq!(
        with_pointer_ranges(|| {
            // SAFETY: The aligned slot is exclusively writable through the scope.
            unsafe { write_i32(&mut flag_out, 1) }
        }),
        CRYPTO_OK
    );
    assert_eq!(len_out, 7);
    assert_eq!(flag_out, 1);
}

#[test]
fn foreign_memory_access_without_a_scope_fails_closed() {
    let mut bytes = [0xa5_u8; 8];
    let mut length = usize::MAX;
    let mut flag = -1_i32;
    // SAFETY: These live, initialized allocations cover every declared range.
    // Without a scope the helpers must reject them before accessing memory.
    unsafe {
        assert_eq!(
            read_slice(bytes.as_ptr(), bytes.len()),
            Err(CRYPTO_INVALID_ARGUMENT)
        );
        assert_eq!(
            write_slice(bytes.as_mut_ptr(), bytes.len()),
            Err(CRYPTO_INVALID_ARGUMENT)
        );
        assert_eq!(
            write_fixed(bytes.as_mut_ptr(), bytes.len(), &[1]),
            CRYPTO_INVALID_ARGUMENT
        );
        assert_eq!(write_len(&mut length, 0), CRYPTO_INVALID_ARGUMENT);
        assert_eq!(write_i32(&mut flag, 0), CRYPTO_INVALID_ARGUMENT);
    }
    assert_eq!(bytes, [0xa5; 8]);
    assert_eq!(length, usize::MAX);
    assert_eq!(flag, -1);
}

#[test]
fn standalone_scope_rejects_derived_output_overlapping_an_input() {
    let mut bytes = [0xa5_u8; 8];
    let length = bytes.len();
    let pointer = bytes.as_mut_ptr();
    let status = with_pointer_ranges(|| {
        // SAFETY: The input remains live and immutable until the scope ends.
        if unsafe { read_slice(pointer.cast_const(), length) }.is_err() {
            return CRYPTO_INTERNAL_ERROR;
        }
        // SAFETY: The output names live writable storage. Its forbidden overlap
        // must be rejected before any mutable reference or write is created.
        unsafe { write_fixed(pointer, length, &[1, 2, 3]) }
    });
    assert_eq!(status, CRYPTO_INVALID_ARGUMENT);
    assert_eq!(bytes, [0xa5; 8]);
    // A completed scope must not retain stale addresses in the next call.
    assert_eq!(
        with_pointer_ranges(|| {
            // SAFETY: This fresh scope has no inputs; the live output is writable
            // and disjoint from the source array for the entire copy.
            unsafe { write_fixed(pointer, length, &[1]) }
        }),
        CRYPTO_OK
    );
}

#[test]
fn pair_writer_validates_both_buffers_before_either_copy() {
    for (first_len, second_len) in [(1, 2), (2, 1)] {
        let mut first = [0xa5_u8; 2];
        let mut second = [0xa5_u8; 2];
        // SAFETY: Both separate allocations remain live and writable for
        // their declared lengths, and source arrays are independent of them.
        let status = with_pointer_ranges(|| unsafe {
            write_fixed_pair(
                first.as_mut_ptr(),
                first_len,
                &[1, 2],
                second.as_mut_ptr(),
                second_len,
                &[3, 4],
            )
        });
        assert_eq!(status, CRYPTO_BUFFER_TOO_SMALL);
        assert_eq!(first, [0xa5; 2]);
        assert_eq!(second, [0xa5; 2]);
    }
    let mut first = [0xa5_u8; 2];
    let mut second = [0xa5_u8; 2];
    assert_eq!(
        with_pointer_ranges(|| {
            // SAFETY: All source and destination allocations are live and
            // disjoint; output buffers are exclusively writable in the scope.
            unsafe {
                write_fixed_pair(
                    first.as_mut_ptr(),
                    first.len(),
                    &[1, 2],
                    second.as_mut_ptr(),
                    second.len(),
                    &[3, 4],
                )
            }
        }),
        CRYPTO_OK
    );
    assert_eq!(first, [1, 2]);
    assert_eq!(second, [3, 4]);
}

#[test]
fn pair_writer_rejects_late_input_alias_before_mutating_first_output() {
    let mut first = [0xa5_u8; 2];
    let mut input_and_second = [0x5a_u8; 2];
    let input_pointer = input_and_second.as_mut_ptr();
    let status = with_pointer_ranges(|| {
        // SAFETY: This allocation is initialized and lives through the scope.
        if unsafe { read_slice(input_pointer.cast_const(), input_and_second.len()) }.is_err() {
            return CRYPTO_INTERNAL_ERROR;
        }
        // SAFETY: Both destinations name live writable allocations. Rejection
        // must precede construction of the forbidden second mutable reference.
        unsafe {
            write_fixed_pair(
                first.as_mut_ptr(),
                first.len(),
                &[1, 2],
                input_pointer,
                input_and_second.len(),
                &[3, 4],
            )
        }
    });
    assert_eq!(status, CRYPTO_INVALID_ARGUMENT);
    assert_eq!(first, [0xa5; 2]);
    assert_eq!(input_and_second, [0x5a; 2]);
}

#[test]
fn nested_standalone_scope_does_not_erase_outer_inputs() {
    let mut bytes = [0xa5_u8; 8];
    let pointer = bytes.as_mut_ptr();
    assert_eq!(
        with_pointer_ranges(|| {
            // SAFETY: The initialized allocation stays live for the entire scope.
            if unsafe { read_slice(pointer.cast_const(), bytes.len()) }.is_err() {
                return CRYPTO_INTERNAL_ERROR;
            }
            assert_eq!(with_pointer_ranges(|| CRYPTO_OK), CRYPTO_INVALID_ARGUMENT);
            // SAFETY: The output remains live, but must be rejected for overlap
            // with the outer input before any mutable reference is constructed.
            unsafe { write_fixed(pointer, bytes.len(), &[1]) }
        }),
        CRYPTO_INVALID_ARGUMENT
    );
    assert_eq!(bytes, [0xa5; 8]);
}

#[test]
#[allow(clippy::panic)]
fn standalone_scope_clears_range_metadata_during_unwind() {
    let bytes = [0xa5_u8; 8];
    let result = std::panic::catch_unwind(|| {
        with_pointer_ranges(|| {
            // SAFETY: The initialized allocation lives beyond this scope.
            assert!(unsafe { read_slice(bytes.as_ptr(), bytes.len()) }.is_ok());
            panic!("exercise pointer-range scope cleanup")
        })
    });
    assert!(result.is_err());
    assert_eq!(with_pointer_ranges(|| CRYPTO_OK), CRYPTO_OK);
}

#[test]
fn wrapping_byte_ranges_fail_validation_without_dereferencing() {
    let pointer = core::ptr::without_provenance_mut::<u8>(usize::MAX);
    assert_eq!(validate_read_pair(pointer, 2), Err(CRYPTO_INVALID_ARGUMENT));
    assert_eq!(
        validate_write_pair(pointer, 2),
        Err(CRYPTO_INVALID_ARGUMENT)
    );
    // Zero-length pointers retain their existing no-access semantics.
    assert_eq!(validate_read_pair(pointer, 0), Ok(()));
    assert_eq!(validate_write_pair(pointer, 0), Ok(()));
}
