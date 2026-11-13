// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{public_key_error, JwtError};

#[test]
fn public_key_context_preserves_canonical_provider_and_backend_reasons() {
    assert_eq!(
        public_key_error(JwtError::PRIMITIVE_INVALID_KEY),
        JwtError::PRIMITIVE_INVALID_PUBLIC_KEY
    );
    for error in [
        JwtError::PRIMITIVE_INVALID_PUBLIC_KEY,
        JwtError::PRIMITIVE_INVALID_PARAMETER,
        JwtError::PROVIDER_UNSUPPORTED_BACKEND,
        JwtError::PROVIDER_UNAVAILABLE,
        JwtError::BACKEND_INTERNAL,
    ] {
        assert_eq!(public_key_error(error), error);
    }
}
