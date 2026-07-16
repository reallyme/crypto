// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, RngFailureKind, RngOutputKind};
use getrandom::{rand_core::TryRng, SysRng};

pub(crate) fn fill_random(output: &mut [u8]) -> Result<(), CryptoError> {
    SysRng.try_fill_bytes(output).map_err(|_| CryptoError::Rng {
        output: RngOutputKind::Generic,
        kind: RngFailureKind::EntropyUnavailable,
    })
}
