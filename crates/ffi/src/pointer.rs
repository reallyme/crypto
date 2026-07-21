// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::status::{CryptoStatus, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INVALID_ARGUMENT};
use core::cell::RefCell;

const MAX_FFI_SLICE_LEN: usize = isize::MAX.unsigned_abs();
const MAX_FFI_INPUT_RANGES_PER_CALL: usize = 32;
const MAX_FFI_OUTPUT_RANGES_PER_CALL: usize = 32;

#[derive(Clone, Copy)]
struct ByteRange {
    ptr: *const u8,
    len: usize,
}

impl ByteRange {
    const EMPTY: Self = Self {
        ptr: core::ptr::null(),
        len: 0,
    };
}

struct RangeRegistry {
    inputs: [ByteRange; MAX_FFI_INPUT_RANGES_PER_CALL],
    input_count: usize,
    outputs: [ByteRange; MAX_FFI_OUTPUT_RANGES_PER_CALL],
    output_count: usize,
    active: bool,
}

impl RangeRegistry {
    const fn new() -> Self {
        Self {
            inputs: [ByteRange::EMPTY; MAX_FFI_INPUT_RANGES_PER_CALL],
            input_count: 0,
            outputs: [ByteRange::EMPTY; MAX_FFI_OUTPUT_RANGES_PER_CALL],
            output_count: 0,
            active: false,
        }
    }

    fn clear(&mut self) {
        self.inputs.fill(ByteRange::EMPTY);
        self.input_count = 0;
        self.outputs.fill(ByteRange::EMPTY);
        self.output_count = 0;
        self.active = false;
    }
}

std::thread_local! {
    static RANGES: RefCell<RangeRegistry> = const {
        RefCell::new(RangeRegistry::new())
    };
}

/// Per-call guard that clears raw pointer-range metadata after an FFI operation.
pub(crate) struct PointerRangeCallGuard;

impl Drop for PointerRangeCallGuard {
    fn drop(&mut self) {
        let _ = RANGES.try_with(|registry| {
            if let Ok(mut ranges) = registry.try_borrow_mut() {
                ranges.clear();
            }
        });
    }
}

/// Starts raw input/output-range tracking for one exported FFI call.
pub(crate) fn begin_input_range_call() -> Result<PointerRangeCallGuard, CryptoStatus> {
    RANGES
        .try_with(|registry| {
            let mut ranges = registry
                .try_borrow_mut()
                .map_err(|_| CRYPTO_INVALID_ARGUMENT)?;
            if ranges.active {
                return Err(CRYPTO_INVALID_ARGUMENT);
            }
            ranges.clear();
            ranges.active = true;
            Ok(PointerRangeCallGuard)
        })
        .map_err(|_| CRYPTO_INVALID_ARGUMENT)?
}

fn register_input_range(ptr: *const u8, len: usize) -> Result<(), CryptoStatus> {
    if len == 0 {
        return Ok(());
    }
    RANGES
        .try_with(|registry| {
            let mut ranges = registry
                .try_borrow_mut()
                .map_err(|_| CRYPTO_INVALID_ARGUMENT)?;
            if !ranges.active {
                return Ok(());
            }
            for output in &ranges.outputs[..ranges.output_count] {
                validate_disjoint_ranges(ptr, len, output.ptr.cast_mut(), output.len)?;
            }
            if ranges.input_count >= MAX_FFI_INPUT_RANGES_PER_CALL {
                return Err(CRYPTO_INVALID_ARGUMENT);
            }
            let index = ranges.input_count;
            ranges.inputs[index] = ByteRange { ptr, len };
            ranges.input_count = index.checked_add(1).ok_or(CRYPTO_INVALID_ARGUMENT)?;
            Ok(())
        })
        .map_err(|_| CRYPTO_INVALID_ARGUMENT)?
}

fn register_output_range<T>(ptr: *mut T, len_bytes: usize) -> Result<(), CryptoStatus> {
    if len_bytes == 0 {
        return Ok(());
    }
    RANGES
        .try_with(|registry| {
            let mut ranges = registry
                .try_borrow_mut()
                .map_err(|_| CRYPTO_INVALID_ARGUMENT)?;
            if !ranges.active {
                return Ok(());
            }
            for input in &ranges.inputs[..ranges.input_count] {
                validate_disjoint_ranges(input.ptr, input.len, ptr.cast::<u8>(), len_bytes)?;
            }
            for output in &ranges.outputs[..ranges.output_count] {
                // Validation helpers may register the same output more than
                // once while checking a multi-output ABI. Treat an identical
                // range as idempotent, but reject every partial or cross-output
                // overlap before any mutable reference is constructed.
                if output.ptr == ptr.cast::<u8>().cast_const() && output.len == len_bytes {
                    return Ok(());
                }
                validate_disjoint_ranges(output.ptr, output.len, ptr.cast::<u8>(), len_bytes)?;
            }
            if ranges.output_count >= MAX_FFI_OUTPUT_RANGES_PER_CALL {
                return Err(CRYPTO_INVALID_ARGUMENT);
            }
            let index = ranges.output_count;
            ranges.outputs[index] = ByteRange {
                ptr: ptr.cast::<u8>().cast_const(),
                len: len_bytes,
            };
            ranges.output_count = index.checked_add(1).ok_or(CRYPTO_INVALID_ARGUMENT)?;
            Ok(())
        })
        .map_err(|_| CRYPTO_INVALID_ARGUMENT)?
}

fn validate_registered_inputs_against_output<T>(
    output_ptr: *mut T,
    output_len_bytes: usize,
) -> Result<(), CryptoStatus> {
    RANGES
        .try_with(|registry| {
            let ranges = registry.try_borrow().map_err(|_| CRYPTO_INVALID_ARGUMENT)?;
            for input in &ranges.inputs[..ranges.input_count] {
                validate_disjoint_ranges(
                    input.ptr,
                    input.len,
                    output_ptr.cast::<u8>(),
                    output_len_bytes,
                )?;
            }
            Ok(())
        })
        .map_err(|_| CRYPTO_INVALID_ARGUMENT)?
}

fn validate_read_pair(ptr: *const u8, len: usize) -> Result<(), CryptoStatus> {
    validate_nonzero_len(ptr, len)
}

fn validate_write_pair(ptr: *mut u8, len: usize) -> Result<(), CryptoStatus> {
    validate_nonzero_len(ptr, len)
}

fn validate_nonzero_len<T>(ptr: *const T, len: usize) -> Result<(), CryptoStatus> {
    if len == 0 {
        return Ok(());
    }
    if ptr.is_null() {
        return Err(CRYPTO_INVALID_ARGUMENT);
    }
    if len > MAX_FFI_SLICE_LEN {
        return Err(CRYPTO_INVALID_ARGUMENT);
    }
    Ok(())
}

fn validate_output_ptr<T>(ptr: *mut T) -> Result<(), CryptoStatus> {
    if ptr.is_null() {
        return Err(CRYPTO_INVALID_ARGUMENT);
    }
    if !ptr.is_aligned() {
        return Err(CRYPTO_INVALID_ARGUMENT);
    }
    Ok(())
}

fn validate_disjoint_ranges(
    read_ptr: *const u8,
    read_len: usize,
    write_ptr: *mut u8,
    write_len: usize,
) -> Result<(), CryptoStatus> {
    validate_read_pair(read_ptr, read_len)?;
    validate_write_pair(write_ptr, write_len)?;
    if read_len == 0 || write_len == 0 {
        return Ok(());
    }

    let read_start = read_ptr.addr();
    let write_start = write_ptr.addr();
    let read_end = read_start
        .checked_add(read_len)
        .ok_or(CRYPTO_INVALID_ARGUMENT)?;
    let write_end = write_start
        .checked_add(write_len)
        .ok_or(CRYPTO_INVALID_ARGUMENT)?;

    if read_start < write_end && write_start < read_end {
        return Err(CRYPTO_INVALID_ARGUMENT);
    }
    Ok(())
}

/// Builds a read-only slice from a caller-supplied `(ptr, len)` pair.
///
/// A null pointer with `len == 0` yields an empty slice; a null pointer with a
/// non-zero length returns [`CRYPTO_INVALID_ARGUMENT`]. Lengths larger than
/// `isize::MAX` are rejected before calling `from_raw_parts` because Rust slice
/// values must describe one allocation whose total size does not exceed that
/// bound.
///
/// # Safety
///
/// When `len != 0`, `ptr` must point to `len` initialized bytes that remain
/// valid and unmutated for the lifetime `'a` of the returned slice.
pub unsafe fn read_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], CryptoStatus> {
    validate_read_pair(ptr, len)?;
    if len == 0 {
        return Ok(&[]);
    }
    register_input_range(ptr, len)?;
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Builds a mutable slice over a caller-supplied output buffer `(ptr, len)`.
///
/// A null pointer with `len == 0` yields an empty slice; a null pointer with a
/// non-zero length returns [`CRYPTO_INVALID_ARGUMENT`]. Lengths larger than
/// `isize::MAX` are rejected before calling `from_raw_parts_mut` because Rust
/// slice values must describe one allocation whose total size does not exceed
/// that bound.
///
/// # Safety
///
/// When `len != 0`, `ptr` must point to `len` bytes of writable, properly
/// aligned memory that stays valid and exclusively borrowed for the lifetime
/// `'a` of the returned slice.
pub unsafe fn write_slice<'a>(ptr: *mut u8, len: usize) -> Result<&'a mut [u8], CryptoStatus> {
    validate_write_pair(ptr, len)?;
    if len == 0 {
        return Ok(&mut []);
    }
    validate_registered_inputs_against_output(ptr, len)?;
    Ok(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

/// Copies `value` into the output buffer `(ptr, len)`, returning
/// [`crate::status::CRYPTO_BUFFER_TOO_SMALL`] if the
/// buffer cannot hold it and [`crate::status::CRYPTO_OK`] on success.
///
/// # Safety
///
/// When `len != 0`, `ptr` must point to at least `len` bytes of writable,
/// properly aligned memory valid for the duration of the call.
pub unsafe fn write_fixed(ptr: *mut u8, len: usize, value: &[u8]) -> CryptoStatus {
    if validate_write_pair(ptr, len).is_err() {
        return CRYPTO_INVALID_ARGUMENT;
    }
    if len < value.len() {
        return CRYPTO_BUFFER_TOO_SMALL;
    }
    if validate_disjoint_ranges(value.as_ptr(), value.len(), ptr, len).is_err() {
        return CRYPTO_INVALID_ARGUMENT;
    }
    let Ok(out) = (unsafe { write_slice(ptr, len) }) else {
        return CRYPTO_INVALID_ARGUMENT;
    };
    out[..value.len()].copy_from_slice(value);
    crate::status::CRYPTO_OK
}

/// Validates a `*mut usize` output pointer without writing to it.
///
/// Variable-length FFI operations call this before mutating byte outputs so a
/// bad produced-length pointer cannot produce a partial success value.
pub fn validate_len_output(ptr: *mut usize) -> CryptoStatus {
    if validate_output_ptr(ptr).is_err() {
        return CRYPTO_INVALID_ARGUMENT;
    }
    crate::status::CRYPTO_OK
}

/// Validates that a byte output buffer and its produced-length pointer are
/// individually valid and do not overlap.
pub fn validate_output_len_pair(
    output_ptr: *mut u8,
    output_len: usize,
    len_out: *mut usize,
) -> CryptoStatus {
    let len_status = validate_len_output(len_out);
    if len_status != crate::status::CRYPTO_OK {
        return len_status;
    }
    if validate_write_pair(output_ptr, output_len).is_err() {
        return CRYPTO_INVALID_ARGUMENT;
    }
    if let Err(status) = validate_disjoint_ranges(
        output_ptr.cast_const(),
        output_len,
        len_out.cast::<u8>(),
        core::mem::size_of::<usize>(),
    ) {
        return status;
    }
    if let Err(status) = register_output_range(output_ptr, output_len) {
        return status;
    }
    match register_output_range(len_out, core::mem::size_of::<usize>()) {
        Ok(()) => crate::status::CRYPTO_OK,
        Err(status) => status,
    }
}

/// Validates that two byte output buffers are individually valid and disjoint.
pub fn validate_disjoint_output_pair(
    first_ptr: *mut u8,
    first_len: usize,
    second_ptr: *mut u8,
    second_len: usize,
) -> CryptoStatus {
    if let Err(status) =
        validate_disjoint_ranges(first_ptr.cast_const(), first_len, second_ptr, second_len)
    {
        return status;
    }
    if let Err(status) = register_output_range(first_ptr, first_len) {
        return status;
    }
    match register_output_range(second_ptr, second_len) {
        Ok(()) => crate::status::CRYPTO_OK,
        Err(status) => status,
    }
}

/// Validates that a caller-owned input and byte output are individually valid
/// and do not overlap.
///
/// Call this before constructing either Rust slice. Performing the check at
/// the raw-pointer boundary avoids creating references whose aliasing contract
/// the caller has already violated.
pub fn validate_disjoint_input_output_pair(
    input_ptr: *const u8,
    input_len: usize,
    output_ptr: *mut u8,
    output_len: usize,
) -> CryptoStatus {
    match validate_disjoint_ranges(input_ptr, input_len, output_ptr, output_len) {
        Ok(()) => crate::status::CRYPTO_OK,
        Err(status) => status,
    }
}

/// Validates that a caller-owned byte input does not overlap a produced-length
/// pointer.
pub fn validate_disjoint_input_len_pair(
    input_ptr: *const u8,
    input_len: usize,
    len_out: *mut usize,
) -> CryptoStatus {
    if validate_len_output(len_out) != crate::status::CRYPTO_OK {
        return CRYPTO_INVALID_ARGUMENT;
    }
    match validate_disjoint_ranges(
        input_ptr,
        input_len,
        len_out.cast::<u8>(),
        core::mem::size_of::<usize>(),
    ) {
        Ok(()) => crate::status::CRYPTO_OK,
        Err(status) => status,
    }
}

/// Validates that two produced-length output pointers are valid and disjoint.
pub fn validate_disjoint_len_outputs(first: *mut usize, second: *mut usize) -> CryptoStatus {
    let first_status = validate_len_output(first);
    if first_status != crate::status::CRYPTO_OK {
        return first_status;
    }
    let second_status = validate_len_output(second);
    if second_status != crate::status::CRYPTO_OK {
        return second_status;
    }
    if let Err(status) = validate_disjoint_ranges(
        first.cast::<u8>().cast_const(),
        core::mem::size_of::<usize>(),
        second.cast::<u8>(),
        core::mem::size_of::<usize>(),
    ) {
        return status;
    }
    if let Err(status) = register_output_range(first, core::mem::size_of::<usize>()) {
        return status;
    }
    match register_output_range(second, core::mem::size_of::<usize>()) {
        Ok(()) => crate::status::CRYPTO_OK,
        Err(status) => status,
    }
}

/// Writes `value` through a `*mut usize` output pointer (used for the
/// `*_len_out` produced-length parameters), returning
/// [`CRYPTO_INVALID_ARGUMENT`] if the pointer is null.
///
/// # Safety
///
/// `ptr`, when non-null, must point to a writable, properly aligned `usize`
/// valid for the duration of the call.
pub unsafe fn write_len(ptr: *mut usize, value: usize) -> CryptoStatus {
    if validate_output_ptr(ptr).is_err() {
        return CRYPTO_INVALID_ARGUMENT;
    }
    if validate_registered_inputs_against_output(ptr, core::mem::size_of::<usize>()).is_err() {
        return CRYPTO_INVALID_ARGUMENT;
    }
    unsafe {
        *ptr = value;
    }
    crate::status::CRYPTO_OK
}

/// Writes `value` through a `*mut i32` output pointer (used for the
/// `valid_out` / `equal_out` result flags), returning
/// [`CRYPTO_INVALID_ARGUMENT`] if the pointer is null.
///
/// # Safety
///
/// `ptr`, when non-null, must point to a writable, properly aligned `i32`
/// valid for the duration of the call.
pub unsafe fn write_i32(ptr: *mut i32, value: i32) -> CryptoStatus {
    if validate_output_ptr(ptr).is_err() {
        return CRYPTO_INVALID_ARGUMENT;
    }
    if validate_registered_inputs_against_output(ptr, core::mem::size_of::<i32>()).is_err() {
        return CRYPTO_INVALID_ARGUMENT;
    }
    unsafe {
        *ptr = value;
    }
    crate::status::CRYPTO_OK
}
