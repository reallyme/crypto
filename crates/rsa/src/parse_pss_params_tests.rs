// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::parse_rsa_pss_sha2_params;
use crate::{RsaHash, RsaPssParams};
use crypto_core::CryptoError;
use rsa_backend::pkcs8::der::Encode;
#[test]
fn strict_pss_import_rejects_trailing_unknown_and_sha1_defaults() -> Result<(), CryptoError> {
    let source = rsa_backend::pkcs1::RsaPssParamsRef::new::<sha2::Sha256>(32);
    let mut der = source
        .to_der()
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
    assert_eq!(
        parse_rsa_pss_sha2_params(&der)?,
        RsaPssParams {
            message_hash: RsaHash::Sha256,
            mgf1_hash: RsaHash::Sha256,
            salt_len: 32
        }
    );
    let mut inner_trailing = der.clone();
    inner_trailing[1] += 2;
    inner_trailing.extend_from_slice(&[5, 0]);
    assert!(parse_rsa_pss_sha2_params(&inner_trailing).is_err());
    der.push(0);
    assert!(parse_rsa_pss_sha2_params(&der).is_err());
    assert!(parse_rsa_pss_sha2_params(&[0x30, 0]).is_err());
    assert!(parse_rsa_pss_sha2_params(&[0; 513]).is_err());
    Ok(())
}
