// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{EcdsaError, EcdsaHash, EcdsaInput};

pub(super) fn with_digest<T>(
    input: EcdsaInput<'_>,
    operation: impl FnOnce(EcdsaHash, &[u8]) -> Result<T, EcdsaError>,
) -> Result<T, EcdsaError> {
    match input {
        EcdsaInput::Message {
            hash: EcdsaHash::Sha256,
            bytes,
        } => {
            let digest = crypto_sha2_256::digest(bytes);
            operation(EcdsaHash::Sha256, digest.as_bytes())
        }
        EcdsaInput::Message {
            hash: EcdsaHash::Sha384,
            bytes,
        } => {
            let digest = crypto_sha2::digest_sha2_384(bytes);
            operation(EcdsaHash::Sha384, digest.as_bytes())
        }
        EcdsaInput::Message {
            hash: EcdsaHash::Sha512,
            bytes,
        } => {
            let digest = crypto_sha2::digest_sha2_512(bytes);
            operation(EcdsaHash::Sha512, digest.as_bytes())
        }
        EcdsaInput::Prehash { hash, bytes } => {
            let length = match hash {
                EcdsaHash::Sha256 => crypto_sha2_256::SHA2_256_DIGEST_LENGTH,
                EcdsaHash::Sha384 => crypto_sha2::SHA2_384_DIGEST_LENGTH,
                EcdsaHash::Sha512 => crypto_sha2::SHA2_512_DIGEST_LENGTH,
            };
            if bytes.len() != length {
                return Err(EcdsaError::InvalidPrehashLength);
            }
            operation(hash, bytes)
        }
    }
}
