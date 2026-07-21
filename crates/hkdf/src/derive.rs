// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, HkdfFailureKind, HkdfHash};
use hkdf::Hkdf;
#[cfg(feature = "sha3")]
use hkdf::SimpleHkdf;
use sha2::{Sha256, Sha384};
#[cfg(feature = "sha3")]
use sha3::Sha3_256;

use crate::material::{HkdfInfo, HkdfInputKeyMaterial, HkdfOutput, HkdfSalt};
use crate::policy::{DomainKeyPurpose, DomainTag, HkdfSuite};

/// Parameters for a single HKDF extract-and-expand derivation.
pub struct DeriveRequest<'a> {
    /// Hash suite to use.
    pub suite: HkdfSuite,
    /// Input keying material to extract from.
    pub ikm: &'a HkdfInputKeyMaterial,
    /// Optional salt for the extract step.
    pub salt: Option<&'a HkdfSalt>,
    /// Context/application-binding `info` for the expand step.
    pub info: &'a HkdfInfo,
}

/// Run HKDF-Expand for `request`, producing `N` bytes of output.
///
/// Errors if the input keying material is empty or `N` is zero.
///
pub fn derive<const N: usize>(request: &DeriveRequest<'_>) -> Result<HkdfOutput<N>, CryptoError> {
    if request.ikm.as_bytes().is_empty() {
        return Err(CryptoError::Hkdf {
            hash: request.suite.hash(),
            kind: HkdfFailureKind::InvalidIkmLength,
        });
    }

    if N == 0 {
        return Err(CryptoError::Hkdf {
            hash: request.suite.hash(),
            kind: HkdfFailureKind::InvalidOutputLength,
        });
    }

    let mut output = [0u8; N];

    match request.suite {
        HkdfSuite::Sha2_256 => {
            let hkdf =
                Hkdf::<Sha256>::new(request.salt.map(HkdfSalt::as_bytes), request.ikm.as_bytes());
            hkdf.expand(request.info.as_bytes(), &mut output)
                .map_err(|_| CryptoError::Hkdf {
                    hash: HkdfHash::Sha2_256,
                    kind: HkdfFailureKind::ExpandFailed,
                })?;
        }
        HkdfSuite::Sha2_384 => {
            let hkdf =
                Hkdf::<Sha384>::new(request.salt.map(HkdfSalt::as_bytes), request.ikm.as_bytes());
            hkdf.expand(request.info.as_bytes(), &mut output)
                .map_err(|_| CryptoError::Hkdf {
                    hash: HkdfHash::Sha2_384,
                    kind: HkdfFailureKind::ExpandFailed,
                })?;
        }
        HkdfSuite::Sha3_256 => {
            #[cfg(feature = "sha3")]
            {
                // The generic RustCrypto HKDF implementation supports SHA3-256
                // directly. Keeping this path aligned with the SHA-2 suites
                // removes a parallel HMAC implementation and inherits the
                // workspace's zeroizing digest-state feature policy.
                let hkdf = SimpleHkdf::<Sha3_256>::new(
                    request.salt.map(HkdfSalt::as_bytes),
                    request.ikm.as_bytes(),
                );
                hkdf.expand(request.info.as_bytes(), &mut output)
                    .map_err(|_| CryptoError::Hkdf {
                        hash: HkdfHash::Sha3_256,
                        kind: HkdfFailureKind::ExpandFailed,
                    })?;
            }

            #[cfg(not(feature = "sha3"))]
            {
                return Err(CryptoError::Unsupported);
            }
        }
    }

    Ok(HkdfOutput::from_array(output))
}

/// Derive a 32-byte domain-separated key using SHA3-256 HKDF.
///
/// Builds the `info` as `reallyme/crypto/hkdf/v1/<purpose>/<domain_tag>` and
/// expands it; errors on length overflow or an underlying HKDF failure.
/// Returns [`CryptoError::Unsupported`] unless the crate's `sha3` feature is
/// enabled.
pub fn derive_domain_key_32(
    ikm: &HkdfInputKeyMaterial,
    salt: Option<&HkdfSalt>,
    purpose: DomainKeyPurpose,
    domain_tag: &DomainTag,
) -> Result<HkdfOutput<32>, CryptoError> {
    const PREFIX: &[u8] = b"reallyme/crypto/hkdf/v1/";
    const SEPARATOR: &[u8] = b"/";

    let capacity = PREFIX
        .len()
        .checked_add(purpose.as_bytes().len())
        .and_then(|value| value.checked_add(SEPARATOR.len()))
        .and_then(|value| value.checked_add(domain_tag.as_bytes().len()))
        .ok_or(CryptoError::Hkdf {
            hash: HkdfHash::Sha3_256,
            kind: HkdfFailureKind::LengthOverflow,
        })?;

    let mut info = Vec::<u8>::with_capacity(capacity);
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(purpose.as_bytes());
    info.extend_from_slice(SEPARATOR);
    info.extend_from_slice(domain_tag.as_bytes());

    let hkdf_info = HkdfInfo::from_vec(info);
    derive::<32>(&DeriveRequest {
        suite: HkdfSuite::Sha3_256,
        ikm,
        salt,
        info: &hkdf_info,
    })
}
