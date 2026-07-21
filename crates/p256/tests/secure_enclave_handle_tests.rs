// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for Secure Enclave handle encoding boundaries.

use crypto_core::CryptoError;
use crypto_p256::{decode_se_handle, encode_se_handle};

#[test]
fn secure_enclave_handle_round_trips_tag_bytes() -> Result<(), CryptoError> {
    let tag = b"me.really.did.p256";
    let handle = encode_se_handle(tag)?;

    assert_eq!(decode_se_handle(&handle), Some(tag.as_slice()));
    assert_eq!(decode_se_handle(tag), None);
    Ok(())
}
