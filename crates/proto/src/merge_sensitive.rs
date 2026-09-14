// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Secret-aware replacement of generated protobuf scalar fields.

use buffa::{bytes::Buf, DecodeError};
use zeroize::Zeroize;

pub(crate) fn merge_bytes(value: &mut Vec<u8>, buf: &mut impl Buf) -> Result<(), DecodeError> {
    // Protobuf permits repeated singular fields (last value wins). Buffa clears
    // the old length without wiping the storage, leaving truncated secret bytes
    // in spare capacity or freeing them during growth. Wipe before either can
    // happen. Wipe only the live value: wiping retained capacity on every
    // duplicate makes a large field followed by many empty fields quadratic.
    value.as_mut_slice().zeroize();
    value.clear();
    let result = buffa::types::merge_bytes(value, buf);
    if result.is_err() {
        value.zeroize();
    }
    result
}

pub(crate) fn merge_string(value: &mut String, buf: &mut impl Buf) -> Result<(), DecodeError> {
    // Authentication prompts are privacy-bearing even though they are strings.
    value.as_mut_str().zeroize();
    value.clear();
    let result = buffa::types::merge_string(value, buf);
    if result.is_err() {
        // A fragmented input may have been copied before UTF-8 validation
        // clears its length. Wipe spare capacity on this terminal error path.
        value.zeroize();
    }
    result
}

#[cfg(test)]
#[path = "merge_sensitive_tests.rs"]
mod tests;
