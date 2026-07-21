// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Stable wire-error construction for every feature combination.

use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoErrorReason;
use crypto_proto::wire::{CryptoWireError, CryptoWireErrorBranch};

pub(super) fn unsupported_algorithm() -> CryptoWireError {
    wire_error(
        CryptoWireErrorBranch::Provider,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    )
}

#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke",
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "rsa",
        feature = "secp256k1",
        feature = "x25519",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "slh-dsa",
        feature = "x-wing"
    )
))]
pub(super) fn invalid_parameter() -> CryptoWireError {
    wire_error(
        CryptoWireErrorBranch::Primitive,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
    )
}

pub(super) fn wire_error(
    branch: CryptoWireErrorBranch,
    reason: CryptoErrorReason,
) -> CryptoWireError {
    match CryptoWireError::try_new(branch, reason) {
        Ok(error) => error,
        Err(_) => CryptoWireError::malformed_protobuf(),
    }
}
