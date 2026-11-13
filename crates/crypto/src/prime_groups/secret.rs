// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use secrecy::{ExposeSecretMut, SecretSlice};
use zeroize::Zeroizing;

use super::CryptoError;

pub(super) fn zeros(length: usize) -> Result<SecretSlice<u8>, CryptoError> {
    let mut buffer = Zeroizing::new(Vec::new());
    buffer
        .try_reserve_exact(length)
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    buffer.resize(length, 0);
    // Exact capacity avoids an allocator resize copying a secret allocation
    // when Vec becomes Box. Secret bytes enter only after ownership is fixed.
    if buffer.capacity() != length {
        return Err(CryptoError::BACKEND_INTERNAL);
    }
    Ok(SecretSlice::from(
        core::mem::take(&mut *buffer).into_boxed_slice(),
    ))
}

pub(super) fn copy(bytes: &[u8]) -> Result<SecretSlice<u8>, CryptoError> {
    let mut owner = zeros(bytes.len())?;
    owner.expose_secret_mut().copy_from_slice(bytes);
    Ok(owner)
}
