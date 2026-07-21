// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;

/// Secure Enclave handle format:
/// b"SE:" + UTF-8 tag bytes
pub const SE_HANDLE_PREFIX: &[u8] = b"SE:";

/// If `secret` is a Secure Enclave handle, return the tag bytes (UTF-8).
pub fn decode_se_handle(secret: &[u8]) -> Option<&[u8]> {
    secret.strip_prefix(SE_HANDLE_PREFIX)
}

/// Encode a tag into a Secure Enclave handle.
pub fn encode_se_handle(tag: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let capacity = SE_HANDLE_PREFIX
        .len()
        .checked_add(tag.len())
        .ok_or(CryptoError::InvalidKey)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(SE_HANDLE_PREFIX);
    out.extend_from_slice(tag);
    Ok(out)
}
