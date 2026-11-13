// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from the schema descriptor. Regenerate with scripts/generate_error_contract.mjs.

/// Error-envelope branch derived from the schema oneof.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum CryptoErrorBranch {
    /// The primitive error-envelope field.
    Primitive = 1,
    /// The provider error-envelope field.
    Provider = 2,
    /// The backend error-envelope field.
    Backend = 3,
}

/// Canonical schema reason; zero remains available for protobuf defaults.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum CryptoErrorReason {
    /// `CRYPTO_ERROR_REASON_UNSPECIFIED`.
    #[default]
    CRYPTO_ERROR_REASON_UNSPECIFIED = 0,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER = 100,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH = 101,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY = 102,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY = 103,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY = 104,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE = 105,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT = 106,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD = 107,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING = 108,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE = 120,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED`.
    CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED = 121,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED`.
    CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED = 122,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT`.
    CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT = 123,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG = 124,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET`.
    CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET = 125,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF`.
    CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF = 130,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON`.
    CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON = 131,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED`.
    CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED = 132,
    /// `CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION`.
    CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION = 133,
    /// `CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM`.
    CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM = 200,
    /// `CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND`.
    CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND = 201,
    /// `CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE`.
    CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE = 202,
    /// `CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE`.
    CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE = 203,
    /// `CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS`.
    CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS = 204,
    /// `CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND`.
    CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND = 205,
    /// `CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED`.
    CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED = 206,
    /// `CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED`.
    CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED = 207,
    /// `CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED`.
    CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED = 208,
    /// `CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE`.
    CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE = 209,
    /// `CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY`.
    CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY = 210,
    /// `CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE`.
    CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE = 300,
    /// `CRYPTO_ERROR_REASON_BACKEND_INTERNAL`.
    CRYPTO_ERROR_REASON_BACKEND_INTERNAL = 301,
}

impl CryptoErrorReason {
    /// All schema values in numeric order.
    pub const VALUES: &[Self] = &[
        Self::CRYPTO_ERROR_REASON_UNSPECIFIED,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION,
        Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
        Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND,
        Self::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
        Self::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
        Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS,
        Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND,
        Self::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED,
        Self::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED,
        Self::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED,
        Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE,
        Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY,
        Self::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE,
        Self::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
    ];

    /// Stable protobuf numeric identity.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// Stable schema name, independent of backend diagnostic text.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CRYPTO_ERROR_REASON_UNSPECIFIED => "CRYPTO_ERROR_REASON_UNSPECIFIED",
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED"
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION => {
                "CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM => {
                "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND => {
                "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE => {
                "CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE => {
                "CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS => {
                "CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND => {
                "CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED => {
                "CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED => {
                "CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED => {
                "CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE => {
                "CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE"
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY => {
                "CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY"
            }
            Self::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE => {
                "CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE"
            }
            Self::CRYPTO_ERROR_REASON_BACKEND_INTERNAL => "CRYPTO_ERROR_REASON_BACKEND_INTERNAL",
        }
    }

    /// Recognize a schema number, including the protobuf zero sentinel.
    #[must_use]
    pub const fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::CRYPTO_ERROR_REASON_UNSPECIFIED),
            100 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER),
            101 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH),
            102 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY),
            103 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY),
            104 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY),
            105 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE),
            106 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT),
            107 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD),
            108 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING),
            120 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE),
            121 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED),
            122 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED),
            123 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT),
            124 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG),
            125 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET),
            130 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF),
            131 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON),
            132 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED),
            133 => Some(Self::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION),
            200 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM),
            201 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND),
            202 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE),
            203 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE),
            204 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS),
            205 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND),
            206 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED),
            207 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED),
            208 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED),
            209 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE),
            210 => Some(Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY),
            300 => Some(Self::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE),
            301 => Some(Self::CRYPTO_ERROR_REASON_BACKEND_INTERNAL),
            _ => None,
        }
    }

    /// The owning wire branch; an unspecified reason has no owner.
    #[must_use]
    pub const fn branch(self) -> Option<CryptoErrorBranch> {
        match self {
            Self::CRYPTO_ERROR_REASON_UNSPECIFIED => None,
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY => Some(CryptoErrorBranch::Primitive),
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE => Some(CryptoErrorBranch::Primitive),
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT => Some(CryptoErrorBranch::Primitive),
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG => Some(CryptoErrorBranch::Primitive),
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION => {
                Some(CryptoErrorBranch::Primitive)
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM => {
                Some(CryptoErrorBranch::Provider)
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND => {
                Some(CryptoErrorBranch::Provider)
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE => Some(CryptoErrorBranch::Provider),
            Self::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE => {
                Some(CryptoErrorBranch::Provider)
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS => Some(CryptoErrorBranch::Provider),
            Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND => Some(CryptoErrorBranch::Provider),
            Self::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED => Some(CryptoErrorBranch::Provider),
            Self::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED => {
                Some(CryptoErrorBranch::Provider)
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED => Some(CryptoErrorBranch::Provider),
            Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE => {
                Some(CryptoErrorBranch::Provider)
            }
            Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY => {
                Some(CryptoErrorBranch::Provider)
            }
            Self::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE => Some(CryptoErrorBranch::Backend),
            Self::CRYPTO_ERROR_REASON_BACKEND_INTERNAL => Some(CryptoErrorBranch::Backend),
        }
    }

    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_UNSPECIFIED`].
    #[allow(non_upper_case_globals)]
    pub const Unspecified: Self = Self::CRYPTO_ERROR_REASON_UNSPECIFIED;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidParameter: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidLength: Self = Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidKey: Self = Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidPublicKey: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidPrivateKey: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidNonce: Self = Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidSalt: Self = Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidPassword: Self = Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidEncoding: Self = Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidSignature: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveVerificationFailed: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveAuthenticationFailed: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveMalformedCiphertext: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidTag: Self = Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveInvalidSharedSecret: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveMalformedProtobuf: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveMalformedJson: Self = Self::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveResourceLimitExceeded: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION`].
    #[allow(non_upper_case_globals)]
    pub const PrimitiveMissingOperation: Self =
        Self::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM`].
    #[allow(non_upper_case_globals)]
    pub const ProviderUnsupportedAlgorithm: Self =
        Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND`].
    #[allow(non_upper_case_globals)]
    pub const ProviderUnsupportedBackend: Self =
        Self::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE`].
    #[allow(non_upper_case_globals)]
    pub const ProviderUnavailable: Self = Self::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE`].
    #[allow(non_upper_case_globals)]
    pub const ProviderRandomnessUnavailable: Self =
        Self::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS`].
    #[allow(non_upper_case_globals)]
    pub const ProviderKeyExists: Self = Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND`].
    #[allow(non_upper_case_globals)]
    pub const ProviderKeyNotFound: Self = Self::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED`].
    #[allow(non_upper_case_globals)]
    pub const ProviderAccessDenied: Self = Self::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED`].
    #[allow(non_upper_case_globals)]
    pub const ProviderUserAuthenticationRequired: Self =
        Self::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED`].
    #[allow(non_upper_case_globals)]
    pub const ProviderUserCanceled: Self = Self::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE`].
    #[allow(non_upper_case_globals)]
    pub const ProviderHardwareUnavailable: Self =
        Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY`].
    #[allow(non_upper_case_globals)]
    pub const ProviderHardwareRejectedKey: Self =
        Self::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE`].
    #[allow(non_upper_case_globals)]
    pub const BackendInvalidState: Self = Self::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE;
    /// Idiomatic alias for [`Self::CRYPTO_ERROR_REASON_BACKEND_INTERNAL`].
    #[allow(non_upper_case_globals)]
    pub const BackendInternal: Self = Self::CRYPTO_ERROR_REASON_BACKEND_INTERNAL;
}

impl core::fmt::Display for CryptoErrorReason {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Nonzero known reason with fixed diagnostics and no input-bearing fields.
///
/// ```compile_fail
/// use reallyme_crypto_proto::error_types::CryptoError;
/// let _: CryptoError = Default::default();
/// ```
///
/// ```compile_fail
/// use reallyme_crypto_proto::error_types::{CryptoError, CryptoErrorReason};
/// let _ = CryptoError { reason: CryptoErrorReason::Unspecified };
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
#[error("{reason}")]
pub struct CryptoError {
    reason: CryptoErrorReason,
}

impl CryptoError {
    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER`.
    pub const PRIMITIVE_INVALID_PARAMETER: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH`.
    pub const PRIMITIVE_INVALID_LENGTH: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY`.
    pub const PRIMITIVE_INVALID_KEY: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY`.
    pub const PRIMITIVE_INVALID_PUBLIC_KEY: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY`.
    pub const PRIMITIVE_INVALID_PRIVATE_KEY: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE`.
    pub const PRIMITIVE_INVALID_NONCE: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT`.
    pub const PRIMITIVE_INVALID_SALT: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD`.
    pub const PRIMITIVE_INVALID_PASSWORD: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING`.
    pub const PRIMITIVE_INVALID_ENCODING: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE`.
    pub const PRIMITIVE_INVALID_SIGNATURE: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED`.
    pub const PRIMITIVE_VERIFICATION_FAILED: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED`.
    pub const PRIMITIVE_AUTHENTICATION_FAILED: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT`.
    pub const PRIMITIVE_MALFORMED_CIPHERTEXT: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG`.
    pub const PRIMITIVE_INVALID_TAG: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET`.
    pub const PRIMITIVE_INVALID_SHARED_SECRET: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF`.
    pub const PRIMITIVE_MALFORMED_PROTOBUF: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON`.
    pub const PRIMITIVE_MALFORMED_JSON: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED`.
    pub const PRIMITIVE_RESOURCE_LIMIT_EXCEEDED: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION`.
    pub const PRIMITIVE_MISSING_OPERATION: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM`.
    pub const PROVIDER_UNSUPPORTED_ALGORITHM: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND`.
    pub const PROVIDER_UNSUPPORTED_BACKEND: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE`.
    pub const PROVIDER_UNAVAILABLE: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE`.
    pub const PROVIDER_RANDOMNESS_UNAVAILABLE: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS`.
    pub const PROVIDER_KEY_EXISTS: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND`.
    pub const PROVIDER_KEY_NOT_FOUND: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED`.
    pub const PROVIDER_ACCESS_DENIED: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED`.
    pub const PROVIDER_USER_AUTHENTICATION_REQUIRED: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED`.
    pub const PROVIDER_USER_CANCELED: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE`.
    pub const PROVIDER_HARDWARE_UNAVAILABLE: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY`.
    pub const PROVIDER_HARDWARE_REJECTED_KEY: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE`.
    pub const BACKEND_INVALID_STATE: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE,
    };

    /// The schema failure `CRYPTO_ERROR_REASON_BACKEND_INTERNAL`.
    pub const BACKEND_INTERNAL: Self = Self {
        reason: CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
    };

    /// All native failure constants in schema numeric order.
    pub const VALUES: &[Self] = &[
        Self::PRIMITIVE_INVALID_PARAMETER,
        Self::PRIMITIVE_INVALID_LENGTH,
        Self::PRIMITIVE_INVALID_KEY,
        Self::PRIMITIVE_INVALID_PUBLIC_KEY,
        Self::PRIMITIVE_INVALID_PRIVATE_KEY,
        Self::PRIMITIVE_INVALID_NONCE,
        Self::PRIMITIVE_INVALID_SALT,
        Self::PRIMITIVE_INVALID_PASSWORD,
        Self::PRIMITIVE_INVALID_ENCODING,
        Self::PRIMITIVE_INVALID_SIGNATURE,
        Self::PRIMITIVE_VERIFICATION_FAILED,
        Self::PRIMITIVE_AUTHENTICATION_FAILED,
        Self::PRIMITIVE_MALFORMED_CIPHERTEXT,
        Self::PRIMITIVE_INVALID_TAG,
        Self::PRIMITIVE_INVALID_SHARED_SECRET,
        Self::PRIMITIVE_MALFORMED_PROTOBUF,
        Self::PRIMITIVE_MALFORMED_JSON,
        Self::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
        Self::PRIMITIVE_MISSING_OPERATION,
        Self::PROVIDER_UNSUPPORTED_ALGORITHM,
        Self::PROVIDER_UNSUPPORTED_BACKEND,
        Self::PROVIDER_UNAVAILABLE,
        Self::PROVIDER_RANDOMNESS_UNAVAILABLE,
        Self::PROVIDER_KEY_EXISTS,
        Self::PROVIDER_KEY_NOT_FOUND,
        Self::PROVIDER_ACCESS_DENIED,
        Self::PROVIDER_USER_AUTHENTICATION_REQUIRED,
        Self::PROVIDER_USER_CANCELED,
        Self::PROVIDER_HARDWARE_UNAVAILABLE,
        Self::PROVIDER_HARDWARE_REJECTED_KEY,
        Self::BACKEND_INVALID_STATE,
        Self::BACKEND_INTERNAL,
    ];

    /// Validate a reason before constructing a native failure.
    pub const fn try_new(reason: CryptoErrorReason) -> Result<Self, Self> {
        match reason {
            CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED => {
                Err(Self::PRIMITIVE_INVALID_PARAMETER)
            }
            _ => Ok(Self { reason }),
        }
    }

    /// The known, nonzero schema reason.
    #[must_use]
    pub const fn reason(self) -> CryptoErrorReason {
        self.reason
    }

    /// Stable protobuf numeric identity.
    #[must_use]
    pub const fn code(self) -> i32 {
        self.reason.code()
    }
}

impl TryFrom<CryptoErrorReason> for CryptoError {
    type Error = Self;
    fn try_from(reason: CryptoErrorReason) -> Result<Self, Self::Error> {
        Self::try_new(reason)
    }
}

impl TryFrom<i32> for CryptoError {
    type Error = Self;
    fn try_from(code: i32) -> Result<Self, Self::Error> {
        match CryptoErrorReason::from_code(code) {
            Some(reason) => Self::try_new(reason),
            None => Err(Self::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}
