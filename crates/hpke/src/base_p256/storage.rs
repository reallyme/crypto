// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::Zeroizing;

use super::P256BaseError;

pub(super) fn buffer(length: usize) -> Result<Zeroizing<Vec<u8>>, P256BaseError> {
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(length)
        .map_err(|_| P256BaseError::AllocationFailed)?;
    // Reserve while empty, then install initialized clearing storage before
    // copying plaintext or secrets. No sensitive reallocation is required.
    output.resize(length, 0);
    Ok(output)
}
