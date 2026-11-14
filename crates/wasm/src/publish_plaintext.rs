// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use zeroize::Zeroizing;

pub(crate) fn publish_plaintext<T>(
    opened: Result<Zeroizing<Vec<u8>>, CryptoError>,
    publish: impl FnOnce(&[u8]) -> T,
) -> Result<T, CryptoError> {
    // Keep the Rust owner alive until the JS copy completes. Failure has no
    // plaintext owner to pass to the host, so skip the host call entirely.
    opened.map(|plaintext| publish(&plaintext))
}

#[cfg(kani)]
#[path = "publish_plaintext_proof_tests.rs"]
mod proof_tests;
