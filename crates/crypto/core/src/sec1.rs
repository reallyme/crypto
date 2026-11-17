// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const SEC1_COMPRESSED_EVEN_PREFIX: u8 = 0x02;
const SEC1_COMPRESSED_ODD_PREFIX: u8 = 0x03;
const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;

/// Checks the standard SEC1 public-key shapes before a backend parses a point.
///
/// Curve owners supply their fixed compressed and uncompressed lengths. This
/// admits only `0x02 || x`, `0x03 || x`, or `0x04 || x || y`; it deliberately
/// excludes hybrid encodings and the backend's `0x05 || x` compact extension.
/// The caller must still perform curve membership and non-identity validation.
#[doc(hidden)]
pub fn has_standard_sec1_encoding(
    encoded: &[u8],
    compressed_length: usize,
    uncompressed_length: usize,
) -> bool {
    match encoded.first().copied() {
        Some(SEC1_COMPRESSED_EVEN_PREFIX | SEC1_COMPRESSED_ODD_PREFIX) => {
            encoded.len() == compressed_length
        }
        Some(SEC1_UNCOMPRESSED_PREFIX) => encoded.len() == uncompressed_length,
        _ => false,
    }
}

#[cfg(test)]
#[path = "sec1_tests.rs"]
mod tests;
