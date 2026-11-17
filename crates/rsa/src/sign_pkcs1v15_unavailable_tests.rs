// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn signing_without_an_execution_lane_fails_closed() {
    assert!(matches!(
        super::RsaSigningKey::from_pkcs8_der(&[]),
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    ));
}
