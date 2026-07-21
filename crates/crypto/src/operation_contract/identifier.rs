// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Shared generated algorithm-identifier validation.

use buffa::{MessageField, ProtoBox};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    CryptoAlgorithmIdentifier,
};
use crypto_proto::wire::CryptoWireError;

use super::wire_error::invalid_parameter;

pub(super) fn algorithm_branch(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<&ProtoAlgorithmBranch, CryptoWireError> {
    identifier
        .as_option()
        .and_then(|identifier| identifier.algorithm.as_ref())
        .ok_or_else(invalid_parameter)
}
