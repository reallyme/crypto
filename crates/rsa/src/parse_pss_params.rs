// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{RsaHash, RsaPssParams};
use const_oid::AssociatedOid;
use crypto_core::CryptoError;
use rsa_backend::pkcs8::der::{Decode, Encode};

/// Imports complete canonical SHA-2 PSS parameters without tolerating trailing
/// fields, unknown MGF algorithms, or non-NULL hash parameters. Path/profile
/// policy still decides whether independent hashes and salt lengths are allowed.
pub fn parse_rsa_pss_sha2_params(der: &[u8]) -> Result<RsaPssParams, CryptoError> {
    const MAX_PSS_PARAMS_BYTES: usize = 512;
    if der.len() > MAX_PSS_PARAMS_BYTES {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    let params = rsa_backend::pkcs1::RsaPssParamsOwned::from_der(der)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
    let canonical = params
        .to_der()
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
    if canonical.as_slice() != der {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    if params.mask_gen.oid != const_oid::db::rfc5912::ID_MGF_1 {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    let mgf_hash = params
        .mask_gen
        .parameters
        .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
    if params
        .hash
        .parameters
        .as_ref()
        .is_some_and(|value| !value.is_null())
        || mgf_hash
            .parameters
            .as_ref()
            .is_some_and(|value| !value.is_null())
    {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    Ok(RsaPssParams {
        message_hash: sha2_hash(params.hash.oid)?,
        mgf1_hash: sha2_hash(mgf_hash.oid)?,
        salt_len: usize::from(params.salt_len),
    })
}

fn sha2_hash(oid: const_oid::ObjectIdentifier) -> Result<RsaHash, CryptoError> {
    if oid == sha2::Sha256::OID {
        Ok(RsaHash::Sha256)
    } else if oid == sha2::Sha384::OID {
        Ok(RsaHash::Sha384)
    } else if oid == sha2::Sha512::OID {
        Ok(RsaHash::Sha512)
    } else {
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    }
}

#[cfg(feature = "proto")]
impl TryFrom<&crypto_proto::generated::proto::reallyme::crypto::v1::CryptoRsaPssParamsDerRequest>
    for RsaPssParams
{
    type Error = CryptoError;
    fn try_from(
        request: &crypto_proto::generated::proto::reallyme::crypto::v1::CryptoRsaPssParamsDerRequest,
    ) -> Result<Self, Self::Error> {
        parse_rsa_pss_sha2_params(&request.parameters_der)
    }
}

#[cfg(test)]
#[path = "parse_pss_params_tests.rs"]
mod tests;
