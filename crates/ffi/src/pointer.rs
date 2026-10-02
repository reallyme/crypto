// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::status::{CryptoStatus, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INVALID_ARGUMENT};

#[path = "pointer_range_registry.rs"]
mod range_registry;

pub(crate) use range_registry::begin_input_range_call;
use range_registry::{
    register_input_range, register_output_range, validate_registered_inputs_against_output,
    OutputRangeKind,
};

const MAX_FFI_SLICE_LEN: usize = isize::MAX.unsigned_abs();

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
    if len > MAX_FFI_SLICE_LEN || ptr.addr().checked_add(len).is_none() {
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
    // SAFETY: The caller guarantees initialized storage for the returned
    // lifetime. Validation above bounds the length and records this read range
    // so later output slices cannot alias it.
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
    // SAFETY: The caller owns writable storage for the returned lifetime.
    // Validation above bounds the slice and excludes every registered input
    // range, preserving the mutable borrow's aliasing requirement.
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
    // SAFETY: The caller owns `ptr` for this call, and the checks above bound
    // its writable length and exclude overlap with the source bytes.
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
    if let Err(status) = register_output_range(output_ptr, output_len, OutputRangeKind::Bytes) {
        return status;
    }
    match register_output_range(
        len_out,
        core::mem::size_of::<usize>(),
        OutputRangeKind::Length,
    ) {
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
    if let Err(status) = register_output_range(first_ptr, first_len, OutputRangeKind::Bytes) {
        return status;
    }
    match register_output_range(second_ptr, second_len, OutputRangeKind::Bytes) {
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

/// Validates a byte output against a distinct produced-length output.
///
/// Multi-output calls validate each buffer/length pair separately. This
/// cross-pair check prevents an output buffer from aliasing the other pair's
/// length pointer, including when both ranges have the same start and size.
pub fn validate_disjoint_output_len_cross_pair(
    output_ptr: *mut u8,
    output_len: usize,
    len_out: *mut usize,
) -> CryptoStatus {
    if validate_len_output(len_out) != crate::status::CRYPTO_OK {
        return CRYPTO_INVALID_ARGUMENT;
    }
    match validate_disjoint_ranges(
        output_ptr.cast_const(),
        output_len,
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
    if let Err(status) = register_output_range(
        first,
        core::mem::size_of::<usize>(),
        OutputRangeKind::Length,
    ) {
        return status;
    }
    match register_output_range(
        second,
        core::mem::size_of::<usize>(),
        OutputRangeKind::Length,
    ) {
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
    // SAFETY: The caller supplies a writable, aligned usize for this call.
    // The output validation rejects null and input-range aliases before the
    // single write; this function does not retain the pointer.
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
    // SAFETY: The caller supplies a writable, aligned i32 for this call.
    // The output validation rejects null and input-range aliases before the
    // single write; this function does not retain the pointer.
    unsafe {
        *ptr = value;
    }
    crate::status::CRYPTO_OK
}

#[cfg(test)]
#[path = "pointer_tests.rs"]
mod tests;
