// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind, KdfProfile};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SHA-256 digest length in bytes for the JWA Concat KDF profile.
pub const JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH: usize = 32;
/// Maximum accepted ECDH shared-secret length.
pub const JWA_CONCAT_KDF_MAX_SHARED_SECRET_LENGTH: usize = 4096;
/// Maximum accepted AlgorithmID, PartyUInfo, or PartyVInfo byte length.
pub const JWA_CONCAT_KDF_MAX_INFO_LENGTH: usize = 4096;

/// ECDH shared secret `Z` input to Concat KDF.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct JwaSharedSecret {
    bytes: Vec<u8>,
}

impl JwaSharedSecret {
    /// Constructs a shared-secret input for JWA Concat KDF.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.is_empty() || input.len() > JWA_CONCAT_KDF_MAX_SHARED_SECRET_LENGTH {
            return Err(kdf_error(KdfFailureKind::InvalidSecretLength));
        }

        Ok(Self {
            bytes: input.to_vec(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// JOSE/JWA `AlgorithmID` value before its 32-bit length prefix is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwaAlgorithmId {
    bytes: Vec<u8>,
}

impl JwaAlgorithmId {
    /// Constructs an AlgorithmID from its ASCII/UTF-8 bytes, such as `A128GCM`.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.is_empty() || input.len() > JWA_CONCAT_KDF_MAX_INFO_LENGTH {
            return Err(kdf_error(KdfFailureKind::InvalidParams));
        }

        Ok(Self {
            bytes: input.to_vec(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// JOSE/JWA PartyUInfo or PartyVInfo value before length prefixing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwaPartyInfo {
    bytes: Vec<u8>,
}

impl JwaPartyInfo {
    /// Constructs a PartyUInfo or PartyVInfo value. Empty values are valid.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() > JWA_CONCAT_KDF_MAX_INFO_LENGTH {
            return Err(kdf_error(KdfFailureKind::InvalidParams));
        }

        Ok(Self {
            bytes: input.to_vec(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Inputs for JWA ECDH-ES Concat KDF with SHA-256.
pub struct JwaConcatKdfRequest<'a> {
    /// ECDH shared secret `Z`.
    pub shared_secret: &'a JwaSharedSecret,
    /// JWA content-encryption algorithm name, e.g. `A128GCM`.
    pub algorithm_id: &'a JwaAlgorithmId,
    /// Agreement PartyUInfo bytes after base64url decoding.
    pub party_u_info: &'a JwaPartyInfo,
    /// Agreement PartyVInfo bytes after base64url decoding.
    pub party_v_info: &'a JwaPartyInfo,
}

/// Fixed-size Concat KDF output that zeroizes when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct JwaConcatKdfOutput<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> JwaConcatKdfOutput<N> {
    /// Returns the derived key bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the output and returns the derived key bytes.
    pub fn into_bytes(mut self) -> [u8; N] {
        let output = self.bytes;
        self.bytes.zeroize();
        output
    }
}

/// Derives a fixed-size key using the JWA ECDH-ES Concat KDF SHA-256 profile.
pub fn derive_jwa_concat_kdf_sha256<const N: usize>(
    request: &JwaConcatKdfRequest<'_>,
) -> Result<JwaConcatKdfOutput<N>, CryptoError> {
    if N == 0 {
        return Err(kdf_error(KdfFailureKind::InvalidOutputLength));
    }

    let output_bits = N
        .checked_mul(8)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| kdf_error(KdfFailureKind::InvalidOutputLength))?;

    let other_info = build_other_info(
        request.algorithm_id.as_bytes(),
        request.party_u_info.as_bytes(),
        request.party_v_info.as_bytes(),
        output_bits,
    )?;

    let reps = N
        .checked_add(JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH - 1)
        .and_then(|value| value.checked_div(JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH))
        .ok_or_else(|| kdf_error(KdfFailureKind::InvalidOutputLength))?;
    let reps_u32 =
        u32::try_from(reps).map_err(|_| kdf_error(KdfFailureKind::InvalidOutputLength))?;

    let mut derived = vec![0u8; reps * JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH];
    for counter in 1..=reps_u32 {
        let mut hasher = Sha256::new();
        hasher.update(counter.to_be_bytes());
        hasher.update(request.shared_secret.as_bytes());
        hasher.update(&other_info);
        let digest = hasher.finalize();

        let counter_index = usize::try_from(counter - 1)
            .map_err(|_| kdf_error(KdfFailureKind::InvalidOutputLength))?;
        let offset = counter_index
            .checked_mul(JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH)
            .ok_or_else(|| kdf_error(KdfFailureKind::InvalidOutputLength))?;
        let end = offset
            .checked_add(JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH)
            .ok_or_else(|| kdf_error(KdfFailureKind::InvalidOutputLength))?;
        derived[offset..end].copy_from_slice(&digest);
    }

    let mut bytes = [0u8; N];
    bytes.copy_from_slice(&derived[..N]);
    derived.zeroize();

    Ok(JwaConcatKdfOutput { bytes })
}

fn build_other_info(
    algorithm_id: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    output_bits: u32,
) -> Result<Vec<u8>, CryptoError> {
    let capacity = length_prefixed_capacity(algorithm_id)?
        .checked_add(length_prefixed_capacity(party_u_info)?)
        .and_then(|value| value.checked_add(length_prefixed_capacity(party_v_info).ok()?))
        .and_then(|value| value.checked_add(core::mem::size_of::<u32>()))
        .ok_or_else(|| kdf_error(KdfFailureKind::InvalidParams))?;

    let mut other_info = Vec::with_capacity(capacity);
    append_length_prefixed(&mut other_info, algorithm_id)?;
    append_length_prefixed(&mut other_info, party_u_info)?;
    append_length_prefixed(&mut other_info, party_v_info)?;
    other_info.extend_from_slice(&output_bits.to_be_bytes());
    Ok(other_info)
}

fn length_prefixed_capacity(input: &[u8]) -> Result<usize, CryptoError> {
    u32::try_from(input.len()).map_err(|_| kdf_error(KdfFailureKind::InvalidParams))?;
    core::mem::size_of::<u32>()
        .checked_add(input.len())
        .ok_or_else(|| kdf_error(KdfFailureKind::InvalidParams))
}

fn append_length_prefixed(output: &mut Vec<u8>, input: &[u8]) -> Result<(), CryptoError> {
    let len = u32::try_from(input.len()).map_err(|_| kdf_error(KdfFailureKind::InvalidParams))?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(input);
    Ok(())
}

fn kdf_error(kind: KdfFailureKind) -> CryptoError {
    CryptoError::Kdf {
        algorithm: KdfAlgorithm::ConcatKdf,
        profile: KdfProfile::JwaEcdhEsSha256,
        kind,
    }
}
