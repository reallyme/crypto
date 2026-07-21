// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! RSA signature verification facade over the semantic operation owner.

use crypto_core::{CryptoError, SignatureOperation};

use crate::signature_error::crypto_error_from_rsa_operation_error;

pub use crypto_rsa::{
    RsaHash, RsaPssParams, RsaPublicKeyDerEncoding, RSA_MAX_MODULUS_BITS, RSA_MIN_MODULUS_BITS,
    RSA_PUBLIC_KEY_DER_MAX_LEN, RSA_SIGNATURE_MAX_LEN,
};

/// Verifies an RSASSA-PKCS1-v1_5 signature.
pub fn verify_rsa_pkcs1v15(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
    hash: RsaHash,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify_rsa_pkcs1v15(
        public_key_der,
        encoding,
        hash,
        message,
        signature,
    )
    .map_err(|error| crypto_error_from_rsa_operation_error(SignatureOperation::Verify, error))
}

/// Verifies an RSASSA-PSS signature.
pub fn verify_rsa_pss(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
    params: RsaPssParams,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify_rsa_pss(
        public_key_der,
        encoding,
        params,
        message,
        signature,
    )
    .map_err(|error| crypto_error_from_rsa_operation_error(SignatureOperation::Verify, error))
}
