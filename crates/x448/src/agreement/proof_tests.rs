// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::release_shared_secret;
use crate::X448_SHARED_SECRET_LEN;
use crypto_core::CryptoError;

#[kani::proof]
#[kani::unwind(64)]
fn x448_releases_exactly_the_nonzero_backend_outputs() {
    let bytes: [u8; X448_SHARED_SECRET_LEN] = kani::any();
    match release_shared_secret(&bytes) {
        Ok(secret) => {
            assert!(bytes.iter().any(|&byte| byte != 0));
            assert_eq!(secret.as_bytes(), &bytes);
        }
        Err(error) => {
            assert_eq!(bytes, [0; X448_SHARED_SECRET_LEN]);
            assert_eq!(error, CryptoError::PRIMITIVE_INVALID_SHARED_SECRET);
        }
    }
}
