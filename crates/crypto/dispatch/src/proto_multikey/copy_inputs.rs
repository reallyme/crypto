// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::AlgorithmError;
use crypto_core::Algorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoKeyAlgorithmIdentifier, KeyAlgorithm,
};
use zeroize::Zeroizing;

pub(super) fn require_known(known: bool) -> Result<(), AlgorithmError> {
    if known {
        Ok(())
    } else {
        Err(AlgorithmError::PRIMITIVE_INVALID_PARAMETER)
    }
}

// Borrowing the optional value avoids coupling to generated boxed/inline storage.
pub(super) fn read_algorithm(
    value: Option<&CryptoKeyAlgorithmIdentifier>,
) -> Result<Algorithm, AlgorithmError> {
    let value = value.ok_or(AlgorithmError::PRIMITIVE_INVALID_PARAMETER)?;
    Algorithm::try_from(value)
}

pub(super) fn write_algorithm(value: Algorithm) -> CryptoKeyAlgorithmIdentifier {
    CryptoKeyAlgorithmIdentifier {
        algorithm: KeyAlgorithm::from(value).into(),
        __buffa_unknown_fields: Default::default(),
    }
}

pub(super) fn check_length(bytes: &[u8]) -> Result<(), AlgorithmError> {
    u32::try_from(bytes.len())
        .map(|_| ())
        .map_err(|_| AlgorithmError::PRIMITIVE_INVALID_LENGTH)
}

pub(super) fn copy_bytes(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
    let mut output = Zeroizing::new(Vec::new());
    copy_into(&mut output, bytes)?;
    Ok(output)
}

pub(super) fn copy_text(bytes: &[u8]) -> Result<Zeroizing<String>, AlgorithmError> {
    check_length(bytes)?;
    let text =
        core::str::from_utf8(bytes).map_err(|_| AlgorithmError::PRIMITIVE_INVALID_ENCODING)?;
    let mut output = Zeroizing::new(String::new());
    output
        .try_reserve_exact(text.len())
        .map_err(|_| AlgorithmError::BACKEND_INTERNAL)?;
    output.push_str(text);
    Ok(output)
}

// The destination is already a clearing native owner or hardened output DTO.
pub(super) fn copy_into(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AlgorithmError> {
    check_length(bytes)?;
    if !output.is_empty() {
        return Err(AlgorithmError::BACKEND_INVALID_STATE);
    }
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| AlgorithmError::BACKEND_INTERNAL)?;
    output.extend_from_slice(bytes);
    Ok(())
}
