// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Feature-aware KDF request routing.

#[cfg(any(
    all(feature = "kmac", any(feature = "native", feature = "wasm")),
    all(feature = "hkdf", any(feature = "native", feature = "wasm")),
    all(feature = "argon2id", any(feature = "native", feature = "wasm")),
    all(feature = "pbkdf2", any(feature = "native", feature = "wasm")),
    all(feature = "concat-kdf", any(feature = "native", feature = "wasm"))
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoArgon2idDeriveRequest, CryptoHkdfDeriveRequest, CryptoJwaConcatKdfSha256DeriveRequest,
    CryptoKdfDeriveKeyRequest, CryptoKmac256DeriveRequest, CryptoOperationResponse,
};

#[cfg(any(
    all(feature = "kmac", any(feature = "native", feature = "wasm")),
    all(feature = "hkdf", any(feature = "native", feature = "wasm")),
    all(feature = "argon2id", any(feature = "native", feature = "wasm")),
    all(feature = "pbkdf2", any(feature = "native", feature = "wasm")),
    all(feature = "concat-kdf", any(feature = "native", feature = "wasm"))
))]
use super::request::process_request;

pub(super) fn process_kmac256_derive_request(
    request: CryptoKmac256DeriveRequest,
) -> CryptoOperationResponse {
    #[cfg(all(feature = "kmac", any(feature = "native", feature = "wasm")))]
    {
        process_request(
            request,
            super::kdf::process_kmac256_derive,
            CryptoOperationResultBranch::Kmac256Derive,
        )
    }
    #[cfg(not(all(feature = "kmac", any(feature = "native", feature = "wasm"))))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_hkdf_derive_request(
    request: CryptoHkdfDeriveRequest,
) -> CryptoOperationResponse {
    #[cfg(all(feature = "hkdf", any(feature = "native", feature = "wasm")))]
    {
        process_request(
            request,
            super::kdf::process_hkdf_derive,
            CryptoOperationResultBranch::HkdfDerive,
        )
    }
    #[cfg(not(all(feature = "hkdf", any(feature = "native", feature = "wasm"))))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_argon2id_derive_request(
    request: CryptoArgon2idDeriveRequest,
) -> CryptoOperationResponse {
    #[cfg(all(feature = "argon2id", any(feature = "native", feature = "wasm")))]
    {
        process_request(
            request,
            super::kdf::process_argon2id_derive,
            CryptoOperationResultBranch::Argon2idDerive,
        )
    }
    #[cfg(not(all(feature = "argon2id", any(feature = "native", feature = "wasm"))))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_kdf_derive_key_request(
    request: CryptoKdfDeriveKeyRequest,
) -> CryptoOperationResponse {
    #[cfg(all(feature = "pbkdf2", any(feature = "native", feature = "wasm")))]
    {
        process_request(
            request,
            super::kdf::process_kdf_derive_key,
            CryptoOperationResultBranch::KdfDeriveKey,
        )
    }
    #[cfg(not(all(feature = "pbkdf2", any(feature = "native", feature = "wasm"))))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_jwa_concat_kdf_sha256_derive_request(
    request: CryptoJwaConcatKdfSha256DeriveRequest,
) -> CryptoOperationResponse {
    #[cfg(all(feature = "concat-kdf", any(feature = "native", feature = "wasm")))]
    {
        process_request(
            request,
            super::kdf::process_jwa_concat_kdf_sha256_derive,
            CryptoOperationResultBranch::JwaConcatKdfSha256Derive,
        )
    }
    #[cfg(not(all(feature = "concat-kdf", any(feature = "native", feature = "wasm"))))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}
