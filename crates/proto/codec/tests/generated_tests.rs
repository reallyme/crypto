// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for generated codec protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_codec_proto::generated::{
    proto::reallyme::codec::v1::{CodecError, CodecErrorReason, CodecPemError},
    CODEC_PROTO_PACKAGE,
};

#[test]
fn proto_package_name_is_stable() {
    assert_eq!(CODEC_PROTO_PACKAGE, "reallyme.codec.v1");
}

#[test]
fn error_reason_enum_value_is_stable() {
    assert_eq!(
        CodecErrorReason::CODEC_ERROR_REASON_PEM_INVALID_BOUNDARY.to_i32(),
        200
    );
}

#[test]
fn codec_error_envelope_round_trips_with_buffa() {
    let error = CodecError {
        error: CodecPemError {
            reason: EnumValue::from(CodecErrorReason::CODEC_ERROR_REASON_PEM_INVALID_BOUNDARY),
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded = error.encode_to_vec();
    let decoded = CodecError::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(decoded, error);
}
