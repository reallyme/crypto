// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use zeroize::Zeroizing;

pub(super) fn copy_bytes(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut output = Zeroizing::new(Vec::new());
    copy_into(&mut output, bytes)?;
    Ok(output)
}

// The destination is already a clearing native owner or hardened output DTO.
pub(super) fn copy_into(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CryptoError> {
    u32::try_from(bytes.len()).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
    if !output.is_empty() {
        return Err(CryptoError::BACKEND_INVALID_STATE);
    }
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    output.extend_from_slice(bytes);
    Ok(())
}
