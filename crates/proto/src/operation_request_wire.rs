// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Wire helpers for generated operation requests.
//!
//! Keeping binary protobuf and ProtoJSON decoding in this crate prevents the
//! semantic operation contract from growing a parallel wire-format policy.

use crate::generated::proto::reallyme::crypto::v1::{CryptoErrorReason, CryptoOperationRequest};
use crate::wire::{decode_json, decode_protobuf, CryptoWireError, MAX_CRYPTO_PROTO_JSON_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JsonOperationPolicy {
    Allowed,
    SecretBearing,
}

/// Decodes an untrusted binary `CryptoOperationRequest` under the repository's
/// strict protobuf limits.
pub fn decode_operation_request(bytes: &[u8]) -> Result<CryptoOperationRequest, CryptoWireError> {
    decode_protobuf::<CryptoOperationRequest>(bytes)
}

/// Decodes an untrusted generated ProtoJSON `CryptoOperationRequest` under the
/// repository's request-only ProtoJSON policy.
///
/// The JSON route accepts only operations whose request contains no
/// caller-provided private or symmetric key material, password, shared secret,
/// or PSK. Hash and verification inputs can still be confidential and must not
/// be logged. Secret-bearing operations must use binary protobuf so JSON
/// unescaping cannot create an unmanaged temporary copy of key material.
pub fn decode_operation_request_json(
    bytes: &[u8],
) -> Result<CryptoOperationRequest, CryptoWireError> {
    enforce_json_operation_policy(bytes)?;
    decode_json::<CryptoOperationRequest>(bytes)
}

fn enforce_json_operation_policy(bytes: &[u8]) -> Result<(), CryptoWireError> {
    if bytes.len() > MAX_CRYPTO_PROTO_JSON_BYTES {
        return Err(resource_limit_error());
    }

    let mut cursor = skip_json_whitespace(bytes, 0);
    if bytes.get(cursor) != Some(&b'{') {
        return Err(malformed_json_error());
    }
    cursor = skip_json_whitespace(bytes, cursor + 1);

    if bytes.get(cursor) == Some(&b'}') {
        cursor = skip_json_whitespace(bytes, cursor + 1);
        return if cursor == bytes.len() {
            Ok(())
        } else {
            Err(malformed_json_error())
        };
    }
    if bytes.get(cursor) != Some(&b'"') {
        return Err(malformed_json_error());
    }

    let key_start = cursor + 1;
    cursor = key_start;
    while let Some(byte) = bytes.get(cursor) {
        match byte {
            b'"' => break,
            // Generated operation selectors are ASCII identifiers. Rejecting
            // escapes avoids allocating or normalizing an attacker-controlled
            // field name before applying the secret policy.
            b'\\' | 0x00..=0x1f => return Err(malformed_json_error()),
            _ => cursor += 1,
        }
    }
    if bytes.get(cursor) != Some(&b'"') {
        return Err(malformed_json_error());
    }

    let policy =
        classify_json_operation(&bytes[key_start..cursor]).ok_or_else(malformed_json_error)?;
    if policy == JsonOperationPolicy::SecretBearing {
        return Err(secret_json_operation_error());
    }

    cursor = skip_json_whitespace(bytes, cursor + 1);
    if bytes.get(cursor) != Some(&b':') {
        return Err(malformed_json_error());
    }
    ensure_single_top_level_member(bytes, cursor + 1)
}

fn ensure_single_top_level_member(bytes: &[u8], mut cursor: usize) -> Result<(), CryptoWireError> {
    let mut nested_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    while let Some(byte) = bytes.get(cursor) {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            } else if *byte <= 0x1f {
                return Err(malformed_json_error());
            }
            cursor += 1;
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                nested_depth = nested_depth
                    .checked_add(1)
                    .ok_or_else(malformed_json_error)?;
            }
            b'}' if nested_depth == 0 => {
                cursor = skip_json_whitespace(bytes, cursor + 1);
                return if cursor == bytes.len() {
                    Ok(())
                } else {
                    Err(malformed_json_error())
                };
            }
            b'}' | b']' => {
                nested_depth = nested_depth
                    .checked_sub(1)
                    .ok_or_else(malformed_json_error)?;
            }
            b',' if nested_depth == 0 => return Err(malformed_json_error()),
            _ => {}
        }
        cursor += 1;
    }

    Err(malformed_json_error())
}

fn classify_json_operation(key: &[u8]) -> Option<JsonOperationPolicy> {
    let policy = match key {
        b"hash"
        | b"signatureGenerateKeyPair"
        | b"signatureVerify"
        | b"rsaVerify"
        | b"kemGenerateKeyPair"
        | b"kemEncapsulate"
        | b"hpkeGenerateKeyPair"
        | b"hpkeSenderExport" => JsonOperationPolicy::Allowed,
        b"aeadSeal"
        | b"aeadOpen"
        | b"macAuthenticate"
        | b"macVerify"
        | b"signatureDeriveKeyPair"
        | b"signatureSign"
        | b"bip340SchnorrSign"
        | b"keyAgreementDeriveSharedSecret"
        | b"keyAgreementDeriveKeyPair"
        | b"kemDecapsulate"
        | b"kemDeriveKeyPair"
        | b"hkdfDerive"
        | b"kdfDeriveKey"
        | b"jwaConcatKdfSha256Derive"
        | b"kmac256Derive"
        | b"argon2idDerive"
        | b"keyWrap"
        | b"keyUnwrap"
        | b"hpkeSeal"
        | b"hpkeOpen"
        | b"hpkeDeriveKeyPair"
        | b"hpkeReceiverExport"
        | b"hpkePskSeal"
        | b"hpkePskOpen" => JsonOperationPolicy::SecretBearing,
        _ => return None,
    };
    Some(policy)
}

fn skip_json_whitespace(bytes: &[u8], mut cursor: usize) -> usize {
    while matches!(bytes.get(cursor), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        cursor += 1;
    }
    cursor
}

const fn malformed_json_error() -> CryptoWireError {
    CryptoWireError::primitive_internal(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
    )
}

const fn resource_limit_error() -> CryptoWireError {
    CryptoWireError::primitive_internal(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
    )
}

const fn secret_json_operation_error() -> CryptoWireError {
    CryptoWireError::provider_internal(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND,
    )
}
