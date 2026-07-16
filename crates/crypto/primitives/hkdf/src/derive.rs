// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, HkdfFailureKind, HkdfHash};
use hkdf::Hkdf;
use sha2::Sha256;
#[cfg(feature = "sha3")]
use sha3::{Digest, Sha3_256};
#[cfg(feature = "sha3")]
use zeroize::{Zeroize, Zeroizing};

use crate::material::{HkdfInfo, HkdfInputKeyMaterial, HkdfOutput, HkdfSalt};
use crate::policy::{DomainKeyPurpose, DomainTag, HkdfSuite};

#[cfg(feature = "sha3")]
const SHA3_256_DIGEST_LEN: usize = 32;
#[cfg(feature = "sha3")]
const SHA3_256_HMAC_BLOCK_LEN: usize = 136;
#[cfg(feature = "sha3")]
const HKDF_MAX_BLOCKS: usize = 255;

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

#[cfg(feature = "sha3")]
fn hmac_sha3_256(key: &[u8], message: &[u8]) -> [u8; SHA3_256_DIGEST_LEN] {
    let mut key_block = Zeroizing::new([0u8; SHA3_256_HMAC_BLOCK_LEN]);

    if key.len() > SHA3_256_HMAC_BLOCK_LEN {
        let hashed_key = Sha3_256::digest(key);
        key_block[..SHA3_256_DIGEST_LEN].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = Zeroizing::new([0x36u8; SHA3_256_HMAC_BLOCK_LEN]);
    let mut outer_pad = Zeroizing::new([0x5cu8; SHA3_256_HMAC_BLOCK_LEN]);
    for index in 0..SHA3_256_HMAC_BLOCK_LEN {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }

    let mut inner = Sha3_256::new();
    inner.update(&inner_pad[..]);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha3_256::new();
    outer.update(&outer_pad[..]);
    outer.update(inner_digest.as_slice());
    let outer_digest = outer.finalize();

    let mut tag = [0u8; SHA3_256_DIGEST_LEN];
    tag.copy_from_slice(&outer_digest);
    tag
}

#[cfg(feature = "sha3")]
fn derive_sha3_256<const N: usize>(request: &DeriveRequest<'_>) -> Result<[u8; N], CryptoError> {
    let block_count = N
        .checked_add(SHA3_256_DIGEST_LEN - 1)
        .map(|value| value / SHA3_256_DIGEST_LEN)
        .ok_or(CryptoError::Hkdf {
            hash: HkdfHash::Sha3_256,
            kind: HkdfFailureKind::InvalidOutputLength,
        })?;
    if block_count > HKDF_MAX_BLOCKS {
        return Err(CryptoError::Hkdf {
            hash: HkdfHash::Sha3_256,
            kind: HkdfFailureKind::InvalidOutputLength,
        });
    }

    let zero_salt = [0u8; SHA3_256_DIGEST_LEN];
    let salt = match request.salt {
        Some(salt) => salt.as_bytes(),
        None => &zero_salt,
    };
    let mut prk = Zeroizing::new(hmac_sha3_256(salt, request.ikm.as_bytes()));
    let mut output = [0u8; N];
    let mut previous_block = Zeroizing::new(Vec::<u8>::new());
    let mut written = 0usize;

    for block_index in 1..=block_count {
        let capacity = previous_block
            .len()
            .checked_add(request.info.as_bytes().len())
            .and_then(|value| value.checked_add(1))
            .ok_or(CryptoError::Hkdf {
                hash: HkdfHash::Sha3_256,
                kind: HkdfFailureKind::LengthOverflow,
            })?;
        let mut block_input = Zeroizing::new(Vec::<u8>::with_capacity(capacity));
        block_input.extend_from_slice(&previous_block);
        block_input.extend_from_slice(request.info.as_bytes());
        let counter = u8::try_from(block_index).map_err(|_| CryptoError::Hkdf {
            hash: HkdfHash::Sha3_256,
            kind: HkdfFailureKind::InvalidOutputLength,
        })?;
        block_input.push(counter);

        let block = hmac_sha3_256(&*prk, &block_input);
        previous_block.clear();
        previous_block.extend_from_slice(&block);

        let remaining = N.checked_sub(written).ok_or(CryptoError::Hkdf {
            hash: HkdfHash::Sha3_256,
            kind: HkdfFailureKind::LengthOverflow,
        })?;
        let take = remaining.min(SHA3_256_DIGEST_LEN);
        let end = written.checked_add(take).ok_or(CryptoError::Hkdf {
            hash: HkdfHash::Sha3_256,
            kind: HkdfFailureKind::LengthOverflow,
        })?;
        output[written..end].copy_from_slice(&previous_block[..take]);
        written = end;
    }

    prk.zeroize();
    Ok(output)
}

/// Run HKDF-Expand for `request`, producing `N` bytes of output.
///
/// Errors if the input keying material is empty or `N` is zero.
///
/// # Examples
///
/// ```
/// use crypto_hkdf::{derive, DeriveRequest, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt, HkdfSuite};
///
/// # fn main() -> Result<(), crypto_core::CryptoError> {
/// let ikm = HkdfInputKeyMaterial::from_slice(b"shared secret input keying material");
/// let salt = HkdfSalt::from_slice(b"per-exchange salt");
/// let info = HkdfInfo::from_slice(b"reallyme/example/v1");
///
/// let output = derive::<32>(&DeriveRequest {
///     suite: HkdfSuite::Sha2_256,
///     ikm: &ikm,
///     salt: Some(&salt),
///     info: &info,
/// })?;
///
/// // A fixed output length of `N` bytes; the wrapper zeroizes on drop.
/// assert_eq!(output.as_bytes().len(), 32);
/// # Ok(())
/// # }
/// ```
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
        HkdfSuite::Sha3_256 => {
            #[cfg(feature = "sha3")]
            {
                output = derive_sha3_256::<N>(request)?;
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
