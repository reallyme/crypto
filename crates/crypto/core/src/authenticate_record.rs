// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::Zeroizing;

use crate::CryptoError;

/// Internal handoff for workspace backends that consume a postfix tag.
///
/// The backend must authenticate the entire record before returning `Ok(())`.
/// Its typed error is returned without transferring the working buffer.
pub fn authenticate_record<const TAG_LEN: usize>(
    record: &[u8],
    authenticate: impl FnOnce(&mut [u8], &[u8; TAG_LEN]) -> Result<(), CryptoError>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (ciphertext, tag) = record
        .split_last_chunk::<TAG_LEN>()
        .ok_or(CryptoError::PRIMITIVE_MALFORMED_CIPHERTEXT)?;

    // A backend can write candidate plaintext before checking the tag.
    // Reserve while empty and give it only a slice so neither reallocation
    // nor ownership transfer can occur while authentication is in progress.
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(ciphertext.len())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    plaintext.extend_from_slice(ciphertext);

    authenticate(plaintext.as_mut_slice(), tag)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proof_tests;
