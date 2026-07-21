// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated response construction after semantic execution.

use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoOperationResponse, CryptoOperationResult,
};

use super::error::error_response;

pub(super) fn response_from_result<R>(
    result: Result<R, crypto_proto::wire::CryptoWireError>,
    wrap: fn(Box<R>) -> CryptoOperationResultBranch,
) -> CryptoOperationResponse {
    match result {
        Ok(result) => result_response(wrap(Box::new(result))),
        Err(error) => error_response(error),
    }
}

pub(crate) fn result_response(result: CryptoOperationResultBranch) -> CryptoOperationResponse {
    CryptoOperationResponse {
        outcome: Some(CryptoOperationOutcome::Result(Box::new(
            CryptoOperationResult {
                result: Some(result),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    }
}
