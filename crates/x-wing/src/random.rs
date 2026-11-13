// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use getrandom::{rand_core::TryRng, SysRng};

pub(crate) fn fill_random(output: &mut [u8]) -> Result<(), CryptoError> {
    SysRng
        .try_fill_bytes(output)
        .map_err(|_| crypto_core::CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
}
