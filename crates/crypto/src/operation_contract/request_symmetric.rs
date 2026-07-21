// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Feature-aware hash, AEAD, MAC, and key-wrap request routing.

#[cfg(all(
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw"
    ),
    any(feature = "native", feature = "wasm")
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoAeadOpenRequest, CryptoAeadSealRequest, CryptoHashRequest, CryptoKeyUnwrapRequest,
    CryptoKeyWrapRequest, CryptoMacAuthenticateRequest, CryptoMacVerifyRequest,
    CryptoOperationResponse,
};

#[cfg(all(
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw"
    ),
    any(feature = "native", feature = "wasm")
))]
use super::request::process_request;

pub(super) fn process_hash_request(request: CryptoHashRequest) -> CryptoOperationResponse {
    #[cfg(all(
        any(feature = "sha2", feature = "sha3"),
        any(feature = "native", feature = "wasm")
    ))]
    {
        process_request(
            request,
            super::operations::process_hash,
            CryptoOperationResultBranch::Hash,
        )
    }
    #[cfg(not(all(
        any(feature = "sha2", feature = "sha3"),
        any(feature = "native", feature = "wasm")
    )))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_aead_seal_request(request: CryptoAeadSealRequest) -> CryptoOperationResponse {
    #[cfg(all(
        any(
            feature = "aes",
            feature = "aes-gcm-siv",
            feature = "chacha20-poly1305"
        ),
        any(feature = "native", feature = "wasm")
    ))]
    {
        process_request(
            request,
            super::operations::process_aead_seal,
            CryptoOperationResultBranch::AeadSeal,
        )
    }
    #[cfg(not(all(
        any(
            feature = "aes",
            feature = "aes-gcm-siv",
            feature = "chacha20-poly1305"
        ),
        any(feature = "native", feature = "wasm")
    )))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_aead_open_request(request: CryptoAeadOpenRequest) -> CryptoOperationResponse {
    #[cfg(all(
        any(
            feature = "aes",
            feature = "aes-gcm-siv",
            feature = "chacha20-poly1305"
        ),
        any(feature = "native", feature = "wasm")
    ))]
    {
        process_request(
            request,
            super::operations::process_aead_open,
            CryptoOperationResultBranch::AeadOpen,
        )
    }
    #[cfg(not(all(
        any(
            feature = "aes",
            feature = "aes-gcm-siv",
            feature = "chacha20-poly1305"
        ),
        any(feature = "native", feature = "wasm")
    )))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_mac_authenticate_request(
    request: CryptoMacAuthenticateRequest,
) -> CryptoOperationResponse {
    #[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
    {
        process_request(
            request,
            super::operations::process_mac_authenticate,
            CryptoOperationResultBranch::MacAuthenticate,
        )
    }
    #[cfg(not(all(feature = "hmac", any(feature = "native", feature = "wasm"))))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_mac_verify_request(
    request: CryptoMacVerifyRequest,
) -> CryptoOperationResponse {
    #[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
    {
        process_request(
            request,
            super::operations::process_mac_verify,
            CryptoOperationResultBranch::MacVerify,
        )
    }
    #[cfg(not(all(feature = "hmac", any(feature = "native", feature = "wasm"))))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_key_wrap_request(request: CryptoKeyWrapRequest) -> CryptoOperationResponse {
    #[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
    {
        process_request(
            request,
            super::operations::process_key_wrap,
            CryptoOperationResultBranch::KeyWrap,
        )
    }
    #[cfg(not(all(feature = "aes-kw", any(feature = "native", feature = "wasm"))))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_key_unwrap_request(
    request: CryptoKeyUnwrapRequest,
) -> CryptoOperationResponse {
    #[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
    {
        process_request(
            request,
            super::operations::process_key_unwrap,
            CryptoOperationResultBranch::KeyUnwrap,
        )
    }
    #[cfg(not(all(feature = "aes-kw", any(feature = "native", feature = "wasm"))))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}
