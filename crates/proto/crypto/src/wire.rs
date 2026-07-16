// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Lossless protobuf boundary helpers.
//!
//! Native SDK facades intentionally expose small ergonomic error enums. This
//! module is the lower-level wire contract: it preserves whether a failure is
//! primitive-, provider-, or backend-owned and keeps the exact protobuf reason
//! code intact when serialized error bytes need to pass through a service or
//! FFI-style boundary.

use buffa::{DecodeOptions, EnumValue, Message};
use crypto_core::{
    AeadFailureKind, ConstantTimeFailureKind, CryptoError, HkdfFailureKind, KdfFailureKind,
    KemFailureKind, KeyAgreementFailureKind, KeyWrapFailureKind, MacFailureKind, RngFailureKind,
    SignatureFailureKind,
};
use serde::de::DeserializeOwned;

use crate::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch, CryptoBackendError,
    CryptoError as ProtoCryptoError, CryptoErrorReason, CryptoPrimitiveError,
    CryptoProtoResultEnvelope, CryptoProtoResultStatus, CryptoProviderError,
};
use zeroize::{Zeroize, Zeroizing};

const CRYPTO_PROTO_RECURSION_LIMIT: u32 = 64;
const CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT: usize = 4_096;
const MAX_CRYPTO_PROTO_ENVELOPE_OVERHEAD_BYTES: usize = 32;
const PRIMITIVE_REASON_CODE_RANGE: core::ops::RangeInclusive<i32> = 100..=199;
const PROVIDER_REASON_CODE_RANGE: core::ops::RangeInclusive<i32> = 200..=299;
const BACKEND_REASON_CODE_RANGE: core::ops::RangeInclusive<i32> = 300..=399;

/// Maximum accepted protobuf message size at the crypto wire boundary.
pub const MAX_CRYPTO_PROTO_MESSAGE_BYTES: usize = 1024 * 1024;

/// Maximum accepted JSON message size at the crypto wire boundary.
pub const MAX_CRYPTO_PROTO_JSON_BYTES: usize = 1_572_864;

/// Maximum encoded size accepted for a standalone serialized `CryptoError`.
pub const CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT: usize = 1024;

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

/// Status attached to bytes returned by a protobuf-facing operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoProtoStatus {
    /// `bytes` contains a successful operation result protobuf.
    Result,
    /// `bytes` contains a serialized [`ProtoCryptoError`].
    CryptoError,
}

/// Codec-style result envelope for operations that return protobuf bytes.
pub struct CryptoProtoResult {
    /// Whether `bytes` is a result message or a structured crypto error.
    pub status: CryptoProtoStatus,
    /// Serialized protobuf bytes for the result or [`ProtoCryptoError`].
    ///
    /// Successful result messages may contain plaintext, secret keys, shared
    /// secrets, passwords, salts, derived keys, or other secret-bearing bytes
    /// depending on the operation. The wire envelope owns these bytes only until
    /// it is handed to an FFI/WASM/JNI/platform caller; consumers must treat the
    /// buffer according to the operation contract and clear managed-runtime
    /// copies where platform semantics permit.
    bytes: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for CryptoProtoResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CryptoProtoResult")
            .field("status", &self.status)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl CryptoProtoResult {
    /// Wraps successful protobuf bytes.
    pub fn result(bytes: Vec<u8>) -> Self {
        Self {
            status: CryptoProtoStatus::Result,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Serializes a structured crypto error and wraps it as an error result.
    pub fn crypto_error(error: CryptoWireError) -> Self {
        Self {
            status: CryptoProtoStatus::CryptoError,
            bytes: Zeroizing::new(error.encode_to_vec()),
        }
    }

    /// Serializes a successful protobuf message into a result envelope.
    pub fn from_message(message: &impl Message) -> Self {
        Self::result(message.encode_to_vec())
    }

    /// Converts a normal Rust result into result-or-error protobuf bytes.
    pub fn from_result<T, F>(result: Result<T, CryptoError>, encode: F) -> Self
    where
        F: FnOnce(T) -> Vec<u8>,
    {
        match result {
            Ok(value) => Self::result(encode(value)),
            Err(error) => Self::crypto_error(CryptoWireError::from(error)),
        }
    }

    /// Best-effort zeroizes and clears the owned protobuf bytes.
    ///
    /// This is useful when callers inspect a `CryptoProtoResult` directly in
    /// Rust. Once bytes have crossed into Swift, Kotlin, TypeScript, JNI, FFI,
    /// or WASM storage, the receiving lane's cleanup rules apply instead.
    pub fn zeroize_bytes(&mut self) {
        self.bytes.zeroize();
    }

    /// Borrows the owned protobuf bytes without creating another secret copy.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Returns the number of owned protobuf bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the owned protobuf byte buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Encodes a protobuf message with Buffa.
pub fn encode_protobuf<M: Message>(message: &M) -> Vec<u8> {
    message.encode_to_vec()
}

/// Decodes a bounded protobuf message from untrusted bytes.
pub fn decode_protobuf<M: Message>(bytes: &[u8]) -> Result<M, CryptoWireError> {
    decode_protobuf_with_limit(bytes, MAX_CRYPTO_PROTO_MESSAGE_BYTES)
}

fn decode_protobuf_with_limit<M: Message>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<M, CryptoWireError> {
    if bytes.len() > max_bytes {
        return Err(CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        ));
    }
    DecodeOptions::new()
        .with_recursion_limit(CRYPTO_PROTO_RECURSION_LIMIT)
        .with_unknown_field_limit(CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT)
        .with_max_message_size(max_bytes)
        .decode_from_slice(bytes)
        .map_err(|_| CryptoWireError::malformed_protobuf())
}

/// Decodes a generated protobuf message from proto3-compatible JSON bytes.
pub fn decode_json<M: DeserializeOwned + Message>(bytes: &[u8]) -> Result<M, CryptoWireError> {
    if bytes.len() > MAX_CRYPTO_PROTO_JSON_BYTES {
        return Err(CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        ));
    }

    let message: M = serde_json::from_slice(bytes).map_err(|_| {
        CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_MALFORMED_JSON,
        )
    })?;
    if encode_protobuf(&message).len() > MAX_CRYPTO_PROTO_MESSAGE_BYTES {
        return Err(CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        ));
    }
    Ok(message)
}

/// Encodes a result/error payload into a bounded protobuf result envelope.
pub fn encode_proto_result_envelope(
    result: &CryptoProtoResult,
) -> Result<Vec<u8>, CryptoProtoResult> {
    if result.len() > MAX_CRYPTO_PROTO_MESSAGE_BYTES {
        return Err(resource_limit_result());
    }

    let mut envelope = proto_result_envelope_from_result(result);
    let encoded = encode_protobuf(&envelope);
    envelope.payload.zeroize();
    if encoded.len() > max_crypto_proto_result_envelope_bytes()? {
        return Err(resource_limit_result());
    }
    Ok(encoded)
}

/// Decodes a bounded protobuf result envelope.
pub fn decode_proto_result_envelope(bytes: &[u8]) -> Result<CryptoProtoResult, CryptoProtoResult> {
    let max_bytes = max_crypto_proto_result_envelope_bytes()?;
    if bytes.len() > max_bytes {
        return Err(resource_limit_result());
    }
    let envelope = decode_protobuf_with_limit::<CryptoProtoResultEnvelope>(bytes, max_bytes)
        .map_err(CryptoProtoResult::crypto_error)?;
    crypto_proto_result_from_envelope(envelope)
}

fn crypto_proto_result_from_envelope(
    mut envelope: CryptoProtoResultEnvelope,
) -> Result<CryptoProtoResult, CryptoProtoResult> {
    if envelope.payload.len() > MAX_CRYPTO_PROTO_MESSAGE_BYTES {
        envelope.payload.zeroize();
        return Err(resource_limit_result());
    }

    let status = match envelope.status.as_known() {
        Some(CryptoProtoResultStatus::CRYPTO_PROTO_RESULT_STATUS_RESULT) => {
            CryptoProtoStatus::Result
        }
        Some(CryptoProtoResultStatus::CRYPTO_PROTO_RESULT_STATUS_CRYPTO_ERROR) => {
            if CryptoWireError::decode(&envelope.payload).is_err() {
                envelope.payload.zeroize();
                return Err(CryptoProtoResult::crypto_error(
                    CryptoWireError::malformed_protobuf(),
                ));
            }
            CryptoProtoStatus::CryptoError
        }
        Some(CryptoProtoResultStatus::CRYPTO_PROTO_RESULT_STATUS_UNSPECIFIED) | None => {
            envelope.payload.zeroize();
            return Err(CryptoProtoResult::crypto_error(
                CryptoWireError::malformed_protobuf(),
            ));
        }
    };

    let bytes = core::mem::take(&mut envelope.payload);
    Ok(CryptoProtoResult {
        status,
        bytes: Zeroizing::new(bytes),
    })
}

fn proto_result_envelope_from_result(result: &CryptoProtoResult) -> CryptoProtoResultEnvelope {
    let status = match result.status {
        CryptoProtoStatus::Result => CryptoProtoResultStatus::CRYPTO_PROTO_RESULT_STATUS_RESULT,
        CryptoProtoStatus::CryptoError => {
            CryptoProtoResultStatus::CRYPTO_PROTO_RESULT_STATUS_CRYPTO_ERROR
        }
    };
    CryptoProtoResultEnvelope {
        status: EnumValue::from(status),
        payload: result.bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn max_crypto_proto_result_envelope_bytes() -> Result<usize, CryptoProtoResult> {
    MAX_CRYPTO_PROTO_MESSAGE_BYTES
        .checked_add(MAX_CRYPTO_PROTO_ENVELOPE_OVERHEAD_BYTES)
        .ok_or_else(|| {
            CryptoProtoResult::crypto_error(CryptoWireError::backend_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
            ))
        })
}

fn resource_limit_result() -> CryptoProtoResult {
    CryptoProtoResult::crypto_error(CryptoWireError::backend_internal(
        CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
    ))
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

    /// Deterministic backend error used when an error envelope is malformed.
    pub const fn malformed_protobuf() -> Self {
        Self::backend_internal(CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF)
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
                | CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF
                | CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_MALFORMED_JSON
                | CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED
        ),
    }
}

impl From<CryptoError> for CryptoWireError {
    fn from(value: CryptoError) -> Self {
        match value {
            CryptoError::InvalidKey => Self::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
            ),
            CryptoError::InvalidAeadKeyLength { .. } => Self::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
            ),
            CryptoError::InvalidAeadNonceLength { .. } => Self::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE,
            ),
            CryptoError::InvalidCiphertextLength { .. } => Self::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
            ),
            CryptoError::AeadEncrypt { kind, .. } => map_aead_failure(kind),
            CryptoError::AeadDecrypt { kind, .. } => map_aead_failure(kind),
            CryptoError::Signature { kind, .. } => map_signature_failure(kind),
            CryptoError::KeyAgreementFailure { kind } => map_key_agreement_failure(kind),
            CryptoError::KemFailure { kind } => map_kem_failure(kind),
            CryptoError::KeyWrap { kind, .. } => map_key_wrap_failure(kind),
            CryptoError::Kdf { kind, .. } => map_kdf_failure(kind),
            CryptoError::Hkdf { kind, .. } => map_hkdf_failure(kind),
            CryptoError::Mac { kind, .. } => map_mac_failure(kind),
            CryptoError::Rng { kind, .. } => map_rng_failure(kind),
            CryptoError::ConstantTimeComparison { kind, .. } => map_constant_time_failure(kind),
            CryptoError::Unsupported => Self::provider_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
            ),
            _ => Self::backend_internal(CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL),
        }
    }
}

fn map_aead_failure(kind: AeadFailureKind) -> CryptoWireError {
    match kind {
        AeadFailureKind::InvalidKeyMaterial => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        ),
        AeadFailureKind::LengthOverflow | AeadFailureKind::InvalidOutputLength => {
            CryptoWireError::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
            )
        }
        AeadFailureKind::ShortCiphertext => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_CIPHERTEXT,
        ),
        AeadFailureKind::AuthenticationFailed => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        ),
        AeadFailureKind::BackendFailure => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_signature_failure(kind: SignatureFailureKind) -> CryptoWireError {
    match kind {
        SignatureFailureKind::InvalidPrivateKey => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
        ),
        SignatureFailureKind::InvalidPublicKey => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY,
        ),
        SignatureFailureKind::InvalidSignature => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
        ),
        SignatureFailureKind::InvalidMessage => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
        ),
        SignatureFailureKind::SecureEnclaveUnavailable => CryptoWireError::provider_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
        ),
        SignatureFailureKind::SecureEnclaveRejectedKey => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        ),
        SignatureFailureKind::BackendFailure | SignatureFailureKind::KeyGenerationFailed => {
            CryptoWireError::backend_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
            )
        }
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_key_agreement_failure(kind: KeyAgreementFailureKind) -> CryptoWireError {
    match kind {
        KeyAgreementFailureKind::DeriveSharedSecretFailed => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SHARED_SECRET,
        ),
        KeyAgreementFailureKind::KeyGenerationFailed => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_kem_failure(kind: KemFailureKind) -> CryptoWireError {
    match kind {
        KemFailureKind::DecapsulateFailed => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        ),
        KemFailureKind::KeyGenerationFailed | KemFailureKind::EncapsulateFailed => {
            CryptoWireError::backend_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
            )
        }
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_key_wrap_failure(kind: KeyWrapFailureKind) -> CryptoWireError {
    match kind {
        KeyWrapFailureKind::InvalidKekLength
        | KeyWrapFailureKind::InvalidPlaintextLength
        | KeyWrapFailureKind::InvalidWrappedLength
        | KeyWrapFailureKind::LengthOverflow => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        KeyWrapFailureKind::IntegrityCheckFailed => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
        ),
        KeyWrapFailureKind::BackendFailure => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_kdf_failure(kind: KdfFailureKind) -> CryptoWireError {
    match kind {
        KdfFailureKind::InvalidSecretLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PASSWORD,
        ),
        KdfFailureKind::InvalidSaltLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SALT,
        ),
        KdfFailureKind::InvalidOutputLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        KdfFailureKind::InvalidIterationCount | KdfFailureKind::InvalidParams => {
            CryptoWireError::primitive_internal(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
            )
        }
        KdfFailureKind::DerivationFailed => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_hkdf_failure(kind: HkdfFailureKind) -> CryptoWireError {
    match kind {
        HkdfFailureKind::InvalidIkmLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        ),
        HkdfFailureKind::InvalidDomainTagLength
        | HkdfFailureKind::LengthOverflow
        | HkdfFailureKind::InvalidOutputLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        HkdfFailureKind::InvalidDomainTagByte => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING,
        ),
        HkdfFailureKind::ExpandFailed => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_mac_failure(kind: MacFailureKind) -> CryptoWireError {
    match kind {
        MacFailureKind::InvalidKeyLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        ),
        MacFailureKind::InvalidTagLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_TAG,
        ),
        MacFailureKind::VerificationFailed => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED,
        ),
        MacFailureKind::BackendFailure => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_rng_failure(kind: RngFailureKind) -> CryptoWireError {
    match kind {
        RngFailureKind::EntropyUnavailable => CryptoWireError::provider_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
        ),
        RngFailureKind::InvalidOutputLength => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn map_constant_time_failure(kind: ConstantTimeFailureKind) -> CryptoWireError {
    match kind {
        ConstantTimeFailureKind::LengthMismatch => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        ),
        ConstantTimeFailureKind::NotEqual => CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED,
        ),
        _ => CryptoWireError::backend_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::generated::proto::reallyme::crypto::v1::CryptoHashRequest;
    use crypto_core::{AeadBackend, SignatureBackend, SignatureOperation};

    #[test]
    fn public_wire_error_constructor_rejects_invalid_branch_reason_pairs() {
        let valid = CryptoWireError::try_new(
            CryptoWireErrorBranch::Provider,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
        )
        .unwrap();
        assert_eq!(valid.branch(), CryptoWireErrorBranch::Provider);
        assert_eq!(
            valid.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE
        );

        let unspecified = CryptoWireError::try_new(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED,
        )
        .unwrap_err();
        assert_eq!(
            unspecified,
            CryptoWireErrorValidationError::UnspecifiedReason
        );

        let mismatch = CryptoWireError::try_new(
            CryptoWireErrorBranch::Provider,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        )
        .unwrap_err();
        assert_eq!(
            mismatch,
            CryptoWireErrorValidationError::BranchReasonMismatch
        );
    }

    #[test]
    fn wire_error_preserves_branch_and_reason_through_bytes() {
        let original = CryptoWireError::try_new(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PRIVATE_KEY,
        )
        .unwrap();
        let decoded = CryptoWireError::decode(&original.encode_to_vec()).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn wire_error_preserves_unknown_reason_code_within_branch_range() {
        const FUTURE_REASON_CODE: i32 = 199;
        let error = ProtoCryptoError {
            error: Some(CryptoErrorBranch::Primitive(Box::new(
                CryptoPrimitiveError {
                    reason: EnumValue::from(FUTURE_REASON_CODE),
                    __buffa_unknown_fields: Default::default(),
                },
            ))),
            __buffa_unknown_fields: Default::default(),
        };

        let decoded = CryptoWireError::decode(&error.encode_to_vec()).unwrap();

        assert_eq!(decoded.branch(), CryptoWireErrorBranch::Primitive);
        assert_eq!(decoded.reason_code(), FUTURE_REASON_CODE);
        assert_eq!(decoded.known_reason(), None);
        assert_eq!(
            decoded.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED
        );
        assert_eq!(
            CryptoWireError::decode(&decoded.encode_to_vec()).unwrap(),
            decoded
        );
    }

    #[test]
    fn wire_error_rejects_unknown_reason_code_outside_branch_range() {
        const INVALID_REASON_CODE: i32 = 777;
        let error = ProtoCryptoError {
            error: Some(CryptoErrorBranch::Primitive(Box::new(
                CryptoPrimitiveError {
                    reason: EnumValue::from(INVALID_REASON_CODE),
                    __buffa_unknown_fields: Default::default(),
                },
            ))),
            __buffa_unknown_fields: Default::default(),
        };

        let decoded = CryptoWireError::decode(&error.encode_to_vec()).unwrap_err();

        assert_eq!(decoded.branch(), CryptoWireErrorBranch::Backend);
        assert_eq!(
            decoded.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF
        );
    }

    #[test]
    fn wire_error_envelope_decode_rejects_oversized_inputs() {
        let oversized = vec![0; CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT + 1];
        let decoded = CryptoWireError::decode(&oversized).unwrap_err();

        assert_eq!(decoded.branch(), CryptoWireErrorBranch::Backend);
        assert_eq!(
            decoded.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF
        );
    }

    #[test]
    fn protobuf_decode_rejects_unknown_field_floods() {
        // Field 2,047 with varint wire type, followed by value zero. The bytes
        // are individually valid but exceed the per-message unknown-field cap.
        const UNKNOWN_FIELD: [u8; 3] = [0xf8, 0x7f, 0x00];
        let mut encoded = Vec::new();
        for _ in 0..=CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT {
            encoded.extend_from_slice(&UNKNOWN_FIELD);
        }

        let error = decode_protobuf::<CryptoHashRequest>(&encoded).unwrap_err();
        assert_eq!(
            error.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF
        );
    }

    #[test]
    fn wire_error_rejects_missing_unspecified_or_mismatched_error_envelopes() {
        let missing = ProtoCryptoError {
            error: None,
            __buffa_unknown_fields: Default::default(),
        };
        let unspecified =
            CryptoWireError::primitive_internal(CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED);
        let mismatched = CryptoWireError::provider_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        );

        for encoded in [
            missing.encode_to_vec(),
            unspecified.encode_to_vec(),
            mismatched.encode_to_vec(),
        ] {
            let decoded = CryptoWireError::decode(&encoded).unwrap_err();
            assert_eq!(decoded.branch(), CryptoWireErrorBranch::Backend);
            assert_eq!(
                decoded.reason(),
                CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF
            );
        }
    }

    #[test]
    fn invalid_inputs_do_not_map_to_authentication_failure() {
        let invalid_key = CryptoWireError::from(CryptoError::InvalidAeadKeyLength {
            expected: 32,
            actual: 31,
        });
        assert_eq!(
            invalid_key.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY
        );

        let invalid_nonce = CryptoWireError::from(CryptoError::InvalidAeadNonceLength {
            expected: 12,
            actual: 11,
        });
        assert_eq!(
            invalid_nonce.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_NONCE
        );

        let invalid_public_key = CryptoWireError::from(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidPublicKey,
        });
        assert_eq!(
            invalid_public_key.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PUBLIC_KEY
        );
    }

    #[test]
    fn authentication_failures_remain_authentication_failures() {
        let auth = CryptoWireError::from(CryptoError::AeadDecrypt {
            backend: AeadBackend::Native,
            kind: AeadFailureKind::AuthenticationFailed,
        });
        assert_eq!(
            auth.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED
        );
    }

    #[test]
    fn proto_result_marks_error_bytes_without_collapsing_reason() {
        let result = CryptoProtoResult::crypto_error(
            CryptoWireError::try_new(
                CryptoWireErrorBranch::Provider,
                CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
            )
            .unwrap(),
        );
        assert_eq!(result.status, CryptoProtoStatus::CryptoError);

        let decoded = CryptoWireError::decode(result.bytes()).unwrap();
        assert_eq!(decoded.branch(), CryptoWireErrorBranch::Provider);
        assert_eq!(
            decoded.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE
        );
    }

    #[test]
    fn proto_result_envelope_round_trips_result_and_error() {
        let success = CryptoProtoResult::result(vec![1, 2, 3]);
        let success_envelope = encode_proto_result_envelope(&success).unwrap();
        let decoded_success = decode_proto_result_envelope(&success_envelope).unwrap();
        assert_eq!(decoded_success.status, success.status);
        assert_eq!(decoded_success.bytes(), success.bytes());

        let error = CryptoProtoResult::crypto_error(
            CryptoWireError::try_new(
                CryptoWireErrorBranch::Provider,
                CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE,
            )
            .unwrap(),
        );
        let error_envelope = encode_proto_result_envelope(&error).unwrap();
        let decoded_error = decode_proto_result_envelope(&error_envelope).unwrap();
        assert_eq!(decoded_error.status, CryptoProtoStatus::CryptoError);
        assert_eq!(
            CryptoWireError::decode(decoded_error.bytes())
                .unwrap()
                .reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNAVAILABLE
        );
    }

    #[test]
    fn proto_result_envelope_rejects_malformed_crypto_error_payloads() {
        let malformed = CryptoProtoResultEnvelope {
            status: EnumValue::from(
                CryptoProtoResultStatus::CRYPTO_PROTO_RESULT_STATUS_CRYPTO_ERROR,
            ),
            payload: vec![0xff],
            __buffa_unknown_fields: Default::default(),
        };

        let rejected = decode_proto_result_envelope(&malformed.encode_to_vec()).unwrap_err();

        assert_eq!(rejected.status, CryptoProtoStatus::CryptoError);
        assert_eq!(
            CryptoWireError::decode(rejected.bytes()).unwrap().reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF
        );
    }

    #[test]
    fn proto_result_envelope_rejects_payloads_over_binary_cap() {
        let oversized = CryptoProtoResult::result(vec![0; MAX_CRYPTO_PROTO_MESSAGE_BYTES + 1]);

        let rejected = encode_proto_result_envelope(&oversized).unwrap_err();

        assert_eq!(rejected.status, CryptoProtoStatus::CryptoError);
        assert_eq!(
            CryptoWireError::decode(rejected.bytes()).unwrap().reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED
        );
    }

    #[test]
    fn proto_result_can_zeroize_owned_bytes() {
        let mut result = CryptoProtoResult::result(vec![1, 2, 3, 4]);

        result.zeroize_bytes();

        assert!(result.is_empty());
    }
}
