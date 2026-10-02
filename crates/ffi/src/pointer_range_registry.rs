// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::validate_disjoint_ranges;
use crate::status::{CryptoStatus, CRYPTO_INVALID_ARGUMENT};
use core::cell::RefCell;

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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OutputRangeKind {
    Bytes,
    Length,
}

#[derive(Clone, Copy)]
struct OutputRange {
    range: ByteRange,
    kind: OutputRangeKind,
}

impl OutputRange {
    const EMPTY: Self = Self {
        range: ByteRange::EMPTY,
        kind: OutputRangeKind::Bytes,
    };
}

struct RangeRegistry {
    inputs: [ByteRange; MAX_FFI_INPUT_RANGES_PER_CALL],
    input_count: usize,
    outputs: [OutputRange; MAX_FFI_OUTPUT_RANGES_PER_CALL],
    output_count: usize,
    active: bool,
}

impl RangeRegistry {
    const fn new() -> Self {
        Self {
            inputs: [ByteRange::EMPTY; MAX_FFI_INPUT_RANGES_PER_CALL],
            input_count: 0,
            outputs: [OutputRange::EMPTY; MAX_FFI_OUTPUT_RANGES_PER_CALL],
            output_count: 0,
            active: false,
        }
    }

    fn clear(&mut self) {
        self.inputs.fill(ByteRange::EMPTY);
        self.input_count = 0;
        self.outputs.fill(OutputRange::EMPTY);
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

pub(super) fn register_input_range(ptr: *const u8, len: usize) -> Result<(), CryptoStatus> {
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
                validate_disjoint_ranges(ptr, len, output.range.ptr.cast_mut(), output.range.len)?;
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

pub(super) fn register_output_range<T>(
    ptr: *mut T,
    len_bytes: usize,
    kind: OutputRangeKind,
) -> Result<(), CryptoStatus> {
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
                // once while checking a multi-output ABI. Re-registration is
                // safe only for the same parameter: a byte buffer must never
                // impersonate a produced-length pointer with identical bytes.
                if output.range.ptr == ptr.cast::<u8>().cast_const()
                    && output.range.len == len_bytes
                {
                    if output.kind == kind {
                        return Ok(());
                    }
                    return Err(CRYPTO_INVALID_ARGUMENT);
                }
                validate_disjoint_ranges(
                    output.range.ptr,
                    output.range.len,
                    ptr.cast::<u8>(),
                    len_bytes,
                )?;
            }
            if ranges.output_count >= MAX_FFI_OUTPUT_RANGES_PER_CALL {
                return Err(CRYPTO_INVALID_ARGUMENT);
            }
            let index = ranges.output_count;
            ranges.outputs[index] = OutputRange {
                range: ByteRange {
                    ptr: ptr.cast::<u8>().cast_const(),
                    len: len_bytes,
                },
                kind,
            };
            ranges.output_count = index.checked_add(1).ok_or(CRYPTO_INVALID_ARGUMENT)?;
            Ok(())
        })
        .map_err(|_| CRYPTO_INVALID_ARGUMENT)?
}

pub(super) fn validate_registered_inputs_against_output<T>(
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
