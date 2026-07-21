// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Platform-key semantic classification tests.

use reallyme_crypto::operations::platform_key::PlatformKeyOperation;
use reallyme_crypto::operations::OperationFamily;

#[test]
fn platform_key_operations_have_one_semantic_family() {
    let operations = [
        PlatformKeyOperation::Generate,
        PlatformKeyOperation::GetPublicKey,
        PlatformKeyOperation::Sign,
        PlatformKeyOperation::Verify,
        PlatformKeyOperation::DeriveSharedSecret,
        PlatformKeyOperation::Delete,
        PlatformKeyOperation::Attest,
    ];

    for operation in operations {
        assert_eq!(operation.family(), OperationFamily::PlatformKey);
    }
}

#[test]
fn platform_key_secret_and_handle_policy_is_explicit() {
    assert!(!PlatformKeyOperation::Generate.requires_existing_key());
    assert!(PlatformKeyOperation::Sign.requires_existing_key());
    assert!(PlatformKeyOperation::DeriveSharedSecret.produces_secret_material());
    assert!(!PlatformKeyOperation::GetPublicKey.produces_secret_material());
}
