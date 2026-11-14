// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed-purpose RFC 5280 method-(1) key identifiers, without ASN.1 extraction.

use crate::native_contract_support::copy_bytes;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoSubjectKeyIdentifierRequest, CryptoSubjectKeyIdentifierResult,
};

/// Hash the exact caller-supplied BIT STRING payload under the existing bounds.
pub fn derive(
    request: &CryptoSubjectKeyIdentifierRequest,
) -> Result<CryptoSubjectKeyIdentifierResult, CryptoError> {
    let identifier = super::subject_key_identifier_sha1(&request.subject_public_key_bits)?;
    let mut output = CryptoSubjectKeyIdentifierResult::default();
    copy_bytes(&mut output.identifier, identifier.as_bytes())?;
    Ok(output)
}
