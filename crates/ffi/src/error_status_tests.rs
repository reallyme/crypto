// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;

use super::{
    aead_open_status, aead_seal_status, hpke_status, kdf_status, kem_decapsulation_status,
    kem_encapsulation_status, key_agreement_status, key_management_status, mac_status, sign_status,
    unwrap_status, verify_status, wrap_status,
};
use crate::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR,
    CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY,
    CRYPTO_INVALID_SIGNATURE, CRYPTO_OK,
};

#[test]
fn c_transport_numbers_remain_unchanged() {
    assert_eq!(
        [
            CRYPTO_OK,
            CRYPTO_INVALID_ARGUMENT,
            CRYPTO_INVALID_KEY,
            CRYPTO_INVALID_SIGNATURE,
            CRYPTO_INVALID_CIPHERTEXT,
            CRYPTO_BUFFER_TOO_SMALL,
            CRYPTO_AUTHENTICATION_FAILED,
            CRYPTO_INTERNAL_ERROR
        ],
        [0, -1, -2, -3, -4, -5, -6, -128]
    );
}

#[test]
fn no_canonical_error_projects_to_success() {
    let errors = [
        CryptoError::PRIMITIVE_INVALID_PARAMETER,
        CryptoError::PRIMITIVE_INVALID_LENGTH,
        CryptoError::PRIMITIVE_INVALID_KEY,
        CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY,
        CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY,
        CryptoError::PRIMITIVE_INVALID_NONCE,
        CryptoError::PRIMITIVE_INVALID_SALT,
        CryptoError::PRIMITIVE_INVALID_PASSWORD,
        CryptoError::PRIMITIVE_INVALID_ENCODING,
        CryptoError::PRIMITIVE_INVALID_SIGNATURE,
        CryptoError::PRIMITIVE_VERIFICATION_FAILED,
        CryptoError::PRIMITIVE_AUTHENTICATION_FAILED,
        CryptoError::PRIMITIVE_MALFORMED_CIPHERTEXT,
        CryptoError::PRIMITIVE_INVALID_TAG,
        CryptoError::PRIMITIVE_INVALID_SHARED_SECRET,
        CryptoError::PRIMITIVE_MALFORMED_PROTOBUF,
        CryptoError::PRIMITIVE_MALFORMED_JSON,
        CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
        CryptoError::PRIMITIVE_MISSING_OPERATION,
        CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM,
        CryptoError::PROVIDER_UNSUPPORTED_BACKEND,
        CryptoError::PROVIDER_UNAVAILABLE,
        CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE,
        CryptoError::PROVIDER_KEY_EXISTS,
        CryptoError::PROVIDER_KEY_NOT_FOUND,
        CryptoError::PROVIDER_ACCESS_DENIED,
        CryptoError::PROVIDER_USER_AUTHENTICATION_REQUIRED,
        CryptoError::PROVIDER_USER_CANCELED,
        CryptoError::PROVIDER_HARDWARE_UNAVAILABLE,
        CryptoError::PROVIDER_HARDWARE_REJECTED_KEY,
        CryptoError::BACKEND_INVALID_STATE,
        CryptoError::BACKEND_INTERNAL,
    ];
    let projectors: &[fn(CryptoError) -> CryptoStatus] = &[
        key_management_status,
        sign_status,
        verify_status,
        key_agreement_status,
        kem_encapsulation_status,
        kem_decapsulation_status,
        wrap_status,
        unwrap_status,
        mac_status,
        kdf_status,
        hpke_status,
        aead_seal_status,
        aead_open_status,
    ];
    for error in errors {
        for projector in projectors {
            assert_ne!(projector(error), CRYPTO_OK);
        }
    }
}

#[test]
fn generic_public_and_private_key_rejections_have_identical_key_status() {
    for error in [
        CryptoError::PRIMITIVE_INVALID_KEY,
        CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY,
        CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY,
    ] {
        for projector in [
            key_management_status,
            sign_status,
            verify_status,
            key_agreement_status,
            kem_encapsulation_status,
            kem_decapsulation_status,
            wrap_status,
            unwrap_status,
            mac_status,
            kdf_status,
            hpke_status,
        ] {
            assert_eq!(projector(error), CRYPTO_INVALID_KEY);
        }
    }
}

#[test]
fn verification_and_authentication_keep_operation_specific_statuses() {
    assert_eq!(
        verify_status(CryptoError::PRIMITIVE_INVALID_SIGNATURE),
        CRYPTO_INVALID_SIGNATURE
    );
    assert_eq!(
        verify_status(CryptoError::PRIMITIVE_VERIFICATION_FAILED),
        CRYPTO_INVALID_SIGNATURE
    );
    assert_eq!(
        verify_status(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED),
        CRYPTO_AUTHENTICATION_FAILED
    );
    assert_eq!(
        mac_status(CryptoError::PRIMITIVE_VERIFICATION_FAILED),
        CRYPTO_AUTHENTICATION_FAILED
    );
    assert_eq!(
        unwrap_status(CryptoError::PRIMITIVE_VERIFICATION_FAILED),
        CRYPTO_AUTHENTICATION_FAILED
    );
    assert_eq!(
        kem_decapsulation_status(CryptoError::PRIMITIVE_VERIFICATION_FAILED),
        CRYPTO_INVALID_CIPHERTEXT
    );
    assert_eq!(
        kem_decapsulation_status(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED),
        CRYPTO_AUTHENTICATION_FAILED
    );
    assert_eq!(
        hpke_status(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED),
        CRYPTO_AUTHENTICATION_FAILED
    );
}

#[test]
fn malformed_ciphertext_and_input_lengths_are_not_internal_failures() {
    assert_eq!(
        unwrap_status(CryptoError::PRIMITIVE_INVALID_LENGTH),
        CRYPTO_INVALID_CIPHERTEXT
    );
    assert_eq!(
        kem_decapsulation_status(CryptoError::PRIMITIVE_INVALID_LENGTH),
        CRYPTO_INVALID_CIPHERTEXT
    );
    assert_eq!(
        hpke_status(CryptoError::PRIMITIVE_INVALID_LENGTH),
        CRYPTO_INVALID_ARGUMENT
    );
    assert_eq!(
        kdf_status(CryptoError::PRIMITIVE_INVALID_PASSWORD),
        CRYPTO_INVALID_KEY
    );
    assert_eq!(
        kdf_status(CryptoError::PRIMITIVE_INVALID_SALT),
        CRYPTO_INVALID_ARGUMENT
    );
}

#[test]
fn backend_and_provider_policy_failures_do_not_become_invalid_input_or_authentication() {
    for error in [
        CryptoError::PROVIDER_UNSUPPORTED_BACKEND,
        CryptoError::PROVIDER_UNAVAILABLE,
        CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE,
        CryptoError::PROVIDER_KEY_EXISTS,
        CryptoError::PROVIDER_KEY_NOT_FOUND,
        CryptoError::PROVIDER_ACCESS_DENIED,
        CryptoError::PROVIDER_USER_AUTHENTICATION_REQUIRED,
        CryptoError::PROVIDER_USER_CANCELED,
        CryptoError::PROVIDER_HARDWARE_UNAVAILABLE,
        CryptoError::PROVIDER_HARDWARE_REJECTED_KEY,
        CryptoError::BACKEND_INVALID_STATE,
        CryptoError::BACKEND_INTERNAL,
    ] {
        assert_eq!(verify_status(error), CRYPTO_INTERNAL_ERROR);
        assert_eq!(kdf_status(error), CRYPTO_INTERNAL_ERROR);
        assert_eq!(aead_open_status(error), CRYPTO_INTERNAL_ERROR);
        assert_eq!(hpke_status(error), CRYPTO_INTERNAL_ERROR);
    }
}

#[test]
fn mac_tag_width_keeps_the_existing_argument_status() {
    assert_eq!(
        super::mac_status(crypto_core::CryptoError::PRIMITIVE_INVALID_TAG),
        crate::status::CRYPTO_INVALID_ARGUMENT,
    );
}
