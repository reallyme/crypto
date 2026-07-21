// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoOperationResponse;
use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome;
use crypto_proto::wire::CryptoWireError;

pub(crate) fn error_response(error: CryptoWireError) -> CryptoOperationResponse {
    CryptoOperationResponse {
        outcome: Some(CryptoOperationOutcome::Error(Box::new(error.to_proto()))),
        __buffa_unknown_fields: Default::default(),
    }
}
