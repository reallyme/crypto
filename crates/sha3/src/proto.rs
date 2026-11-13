// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone SHAKE256 expansion with exact caller-selected output length.
//!
//! The native XOF accepts zero and arbitrary output widths. This adapter does
//! not allocate output, select a provider or register an executable root route.
//! The caller supplies storage under its own resource and cleanup policy. A
//! generated `CryptoShake256ExpandResult.output` is a clearing destination once
//! the caller has initialized its permitted length; `Zeroizing` storage is also
//! supported. Input bytes pass through exactly.

use crypto_proto::error_types::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoShake256ExpandRequest;

/// Expand into the caller's exact-width buffer without allocating or copying
/// the input. Validation completes before the destination can be modified.
/// The caller retains its existing output ownership and cleanup policy.
pub fn expand_into(
    request: &CryptoShake256ExpandRequest,
    output: &mut [u8],
) -> Result<(), CryptoError> {
    let length = output_length(request)?;
    if output.len() != length {
        return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
    }
    crate::shake256_expand(&request.input, output);
    Ok(())
}

fn output_length(request: &CryptoShake256ExpandRequest) -> Result<usize, CryptoError> {
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    usize::try_from(request.output_length).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)
}
