// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::{DecodeOptions, EnumValue, Message};

use crate::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch, CryptoBackendError,
    CryptoError as ProtoCryptoError, CryptoErrorReason, CryptoPrimitiveError, CryptoProviderError,
};

use super::limits::{
    BACKEND_REASON_CODE_RANGE, CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT,
    CRYPTO_PROTO_RECURSION_LIMIT, CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT, PRIMITIVE_REASON_CODE_RANGE,
    PROVIDER_REASON_CODE_RANGE,
};

/// Branch of the protobuf [`CryptoError`](ProtoCryptoError) oneof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoWireErrorBranch {
    /// Primitive validation or cryptographic operation failure.
    Primitive,
    /// Provider policy, support, or availability failure.
    Provider,
    /// Backend dispatch or internal failure.
    Backend,
}

/// Lossless, non-secret representation of a protobuf crypto failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoWireError {
    /// Owning branch of the protobuf error.
    branch: CryptoWireErrorBranch,
    /// Known public protobuf reason, when this version recognizes the code.
    reason: Option<CryptoErrorReason>,
    /// Exact numeric protobuf reason code received or emitted on the wire.
    reason_code: i32,
}

/// Error returned when a public wire error is not branch-valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoWireErrorValidationError {
    /// The reason was `CRYPTO_ERROR_REASON_UNSPECIFIED`.
    #[error("crypto wire error reason is unspecified")]
    UnspecifiedReason,
    /// The reason is not valid for the selected error branch.
    #[error("crypto wire error reason does not match its branch")]
    BranchReasonMismatch,
    /// The numeric reason is outside the reserved range for its branch.
    #[error("crypto wire error reason code is outside its branch range")]
    ReasonCodeOutOfRange,
}

impl CryptoWireError {
    /// Constructs a public wire error after validating branch/reason pairing.
    pub fn try_new(
        branch: CryptoWireErrorBranch,
        reason: CryptoErrorReason,
    ) -> Result<Self, CryptoWireErrorValidationError> {
        if reason == CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED {
            return Err(CryptoWireErrorValidationError::UnspecifiedReason);
        }
        if !reason_matches_branch(branch, reason) {
            return Err(CryptoWireErrorValidationError::BranchReasonMismatch);
        }
        Ok(Self::known_good(branch, reason))
    }

    /// Constructs a wire error from its exact protobuf numeric reason code.
    ///
    /// Unknown values are retained when they are inside the numeric range
    /// reserved for the selected branch. This is the protobuf-compatible path
    /// for forwarding a newer peer's error without weakening branch ownership.
    pub fn try_from_reason_code(
        branch: CryptoWireErrorBranch,
        reason_code: i32,
    ) -> Result<Self, CryptoWireErrorValidationError> {
        if reason_code == CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED as i32 {
            return Err(CryptoWireErrorValidationError::UnspecifiedReason);
        }
        if !reason_code_matches_branch(branch, reason_code) {
            return Err(CryptoWireErrorValidationError::ReasonCodeOutOfRange);
        }

        let reason = EnumValue::<CryptoErrorReason>::from(reason_code).as_known();
        if let Some(known) = reason {
            if !reason_matches_branch(branch, known) {
                return Err(CryptoWireErrorValidationError::BranchReasonMismatch);
            }
        }
        Ok(Self {
            branch,
            reason,
            reason_code,
        })
    }

    /// Owning branch of the protobuf error.
    pub const fn branch(self) -> CryptoWireErrorBranch {
        self.branch
    }

    /// Known public protobuf reason code.
    pub fn reason(self) -> CryptoErrorReason {
        match self.reason {
            Some(reason) => reason,
            None => CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED,
        }
    }

    /// Returns the known reason, or `None` for a forward-compatible code.
    pub const fn known_reason(self) -> Option<CryptoErrorReason> {
        self.reason
    }

    /// Exact numeric protobuf reason code carried on the wire.
    pub const fn reason_code(self) -> i32 {
        self.reason_code
    }

    /// Deterministic primitive boundary error used when an error envelope is malformed.
    pub const fn malformed_protobuf() -> Self {
        Self::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
        )
    }

    const fn known_good(branch: CryptoWireErrorBranch, reason: CryptoErrorReason) -> Self {
        Self {
            branch,
            reason: Some(reason),
            reason_code: reason as i32,
        }
    }

    /// Constructs a primitive-owned wire error from internal known-good mappings.
    pub(crate) const fn primitive_internal(reason: CryptoErrorReason) -> Self {
        Self {
            branch: CryptoWireErrorBranch::Primitive,
            reason: Some(reason),
            reason_code: reason as i32,
        }
    }

    /// Constructs a provider-owned wire error from internal known-good mappings.
    pub(crate) const fn provider_internal(reason: CryptoErrorReason) -> Self {
        Self {
            branch: CryptoWireErrorBranch::Provider,
            reason: Some(reason),
            reason_code: reason as i32,
        }
    }

    /// Constructs a backend-owned wire error from internal known-good mappings.
    pub(crate) const fn backend_internal(reason: CryptoErrorReason) -> Self {
        Self {
            branch: CryptoWireErrorBranch::Backend,
            reason: Some(reason),
            reason_code: reason as i32,
        }
    }

    /// Converts this lossless wrapper into the generated protobuf message.
    pub fn to_proto(self) -> ProtoCryptoError {
        match self.branch {
            CryptoWireErrorBranch::Primitive => ProtoCryptoError {
                error: Some(CryptoErrorBranch::Primitive(Box::new(
                    CryptoPrimitiveError {
                        reason: EnumValue::from(self.reason_code),
                        __buffa_unknown_fields: Default::default(),
                    },
                ))),
                __buffa_unknown_fields: Default::default(),
            },
            CryptoWireErrorBranch::Provider => ProtoCryptoError {
                error: Some(CryptoErrorBranch::Provider(Box::new(CryptoProviderError {
                    reason: EnumValue::from(self.reason_code),
                    __buffa_unknown_fields: Default::default(),
                }))),
                __buffa_unknown_fields: Default::default(),
            },
            CryptoWireErrorBranch::Backend => ProtoCryptoError {
                error: Some(CryptoErrorBranch::Backend(Box::new(CryptoBackendError {
                    reason: EnumValue::from(self.reason_code),
                    __buffa_unknown_fields: Default::default(),
                }))),
                __buffa_unknown_fields: Default::default(),
            },
        }
    }

    /// Encodes this error as structured protobuf bytes.
    pub fn encode_to_vec(self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    /// Parses generated protobuf into the lossless wrapper.
    ///
    /// Error envelopes are intentionally strict: a crypto-error status must
    /// carry a concrete branch and a branch-appropriate, non-unspecified reason
    /// code. Unknown codes within the branch's reserved range are retained.
    /// Malformed error envelopes are represented as backend failures so
    /// callers do not accidentally pass ambiguous or downgradeable error bytes
    /// across a service boundary.
    pub fn from_proto(value: &ProtoCryptoError) -> Self {
        match Self::try_from_proto(value) {
            Ok(error) | Err(error) => error,
        }
    }

    /// Strictly parses generated protobuf into the lossless wrapper.
    pub fn try_from_proto(value: &ProtoCryptoError) -> Result<Self, Self> {
        match &value.error {
            Some(CryptoErrorBranch::Primitive(error)) => {
                Self::from_wire_reason(CryptoWireErrorBranch::Primitive, error.reason)
            }
            Some(CryptoErrorBranch::Provider(error)) => {
                Self::from_wire_reason(CryptoWireErrorBranch::Provider, error.reason)
            }
            Some(CryptoErrorBranch::Backend(error)) => {
                Self::from_wire_reason(CryptoWireErrorBranch::Backend, error.reason)
            }
            None => Err(malformed_error_envelope()),
        }
    }

    fn from_wire_reason(
        branch: CryptoWireErrorBranch,
        reason: EnumValue<CryptoErrorReason>,
    ) -> Result<Self, Self> {
        Self::try_from_reason_code(branch, reason.to_i32()).map_err(|_| malformed_error_envelope())
    }

    /// Decodes structured protobuf error bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Self> {
        let error = DecodeOptions::new()
            .with_recursion_limit(CRYPTO_PROTO_RECURSION_LIMIT)
            .with_unknown_field_limit(CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT)
            .with_max_message_size(CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT)
            .decode_from_slice::<ProtoCryptoError>(bytes)
            .map_err(|_| malformed_error_envelope())?;
        if error.encode_to_vec().len() > CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT {
            return Err(malformed_error_envelope());
        }
        Self::try_from_proto(&error)
    }
}

fn reason_code_matches_branch(branch: CryptoWireErrorBranch, reason_code: i32) -> bool {
    match branch {
        CryptoWireErrorBranch::Primitive => PRIMITIVE_REASON_CODE_RANGE.contains(&reason_code),
        CryptoWireErrorBranch::Provider => PROVIDER_REASON_CODE_RANGE.contains(&reason_code),
        CryptoWireErrorBranch::Backend => BACKEND_REASON_CODE_RANGE.contains(&reason_code),
    }
}

fn malformed_error_envelope() -> CryptoWireError {
    CryptoWireError::malformed_protobuf()
}

fn reason_matches_branch(branch: CryptoWireErrorBranch, reason: CryptoErrorReason) -> bool {
    match branch {
        CryptoWireErrorBranch::Primitive => matches!(
            reason,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION
        ),
        CryptoWireErrorBranch::Provider => matches!(
            reason,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE
                | CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE
        ),
        CryptoWireErrorBranch::Backend => matches!(
            reason,
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE
                | CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL
        ),
    }
}
