// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected standalone retained-record decryption boundary.

use crypto_core::CryptoError;

/// Executes the protected standalone compatibility contract through the same
/// semantic owner used by native callers. No seal or algorithm fallback exists.
pub fn open(
    request: &crypto_proto::generated::proto::reallyme::crypto::v1::CryptoLegacyAes256SivOpenRequest,
) -> Result<
    crypto_proto::generated::proto::reallyme::crypto::v1::CryptoLegacyAes256SivOpenResult,
    CryptoError,
> {
    let plaintext = crate::operations::aead::open_legacy_aes256_siv(
        &request.secret_key,
        &request.nonce,
        &request.associated_data,
        &request.ciphertext,
    )?;
    Ok(
        crypto_proto::generated::proto::reallyme::crypto::v1::CryptoLegacyAes256SivOpenResult {
            plaintext: plaintext.to_vec().into(),
        },
    )
}
