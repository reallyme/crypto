// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, HkdfFailureKind, HkdfHash};
use hkdf::Hkdf;
use sha2::Sha384;

use crate::material::{
    HkdfInfo, HkdfInputKeyMaterial, HkdfOutput, HkdfSalt, HkdfSha384Prk, HKDF_SHA384_PRK_LENGTH,
};

/// Maximum output length permitted by RFC 5869 for HKDF-SHA384.
pub const HKDF_SHA384_MAX_OUTPUT_LENGTH: usize = 12_240;

/// Runs the HKDF-SHA384 extract step and returns its fixed-size secret PRK.
pub fn extract_sha384(
    salt: Option<&HkdfSalt>,
    ikm: &HkdfInputKeyMaterial,
) -> Result<HkdfSha384Prk, CryptoError> {
    if ikm.as_bytes().is_empty() {
        return Err(CryptoError::Hkdf {
            hash: HkdfHash::Sha2_384,
            kind: HkdfFailureKind::InvalidIkmLength,
        });
    }

    let (prk, _) = Hkdf::<Sha384>::extract(salt.map(HkdfSalt::as_bytes), ikm.as_bytes());
    let mut bytes = [0u8; HKDF_SHA384_PRK_LENGTH];
    bytes.copy_from_slice(prk.as_ref());
    Ok(HkdfSha384Prk::from_array(bytes))
}

/// Runs HKDF-SHA384 expand from an extracted PRK.
pub fn expand_sha384<const N: usize>(
    prk: &HkdfSha384Prk,
    info: &HkdfInfo,
) -> Result<HkdfOutput<N>, CryptoError> {
    if N == 0 || N > HKDF_SHA384_MAX_OUTPUT_LENGTH {
        return Err(CryptoError::Hkdf {
            hash: HkdfHash::Sha2_384,
            kind: HkdfFailureKind::InvalidOutputLength,
        });
    }

    let hkdf = Hkdf::<Sha384>::from_prk(prk.as_bytes()).map_err(|_| CryptoError::Hkdf {
        hash: HkdfHash::Sha2_384,
        kind: HkdfFailureKind::InvalidIkmLength,
    })?;
    let mut output = [0u8; N];
    hkdf.expand(info.as_bytes(), &mut output)
        .map_err(|_| CryptoError::Hkdf {
            hash: HkdfHash::Sha2_384,
            kind: HkdfFailureKind::ExpandFailed,
        })?;
    Ok(HkdfOutput::from_array(output))
}
