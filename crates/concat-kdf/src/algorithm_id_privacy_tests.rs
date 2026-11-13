// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{JwaAlgorithmId, JWA_CONCAT_KDF_MAX_INFO_LENGTH};
use zeroize::{Zeroize, ZeroizeOnDrop};

const EXPECTED_DEBUG: &str = "JwaAlgorithmId(<redacted>)";

#[test]
fn algorithm_id_debug_redacts_arbitrary_bytes_and_length() {
    for bytes in [
        vec![0xff],
        b"caller-label\0\xff".to_vec(),
        vec![0xa5; JWA_CONCAT_KDF_MAX_INFO_LENGTH],
    ] {
        let mut identifier = JwaAlgorithmId::from_slice(&bytes).expect("admitted identifier bytes");
        assert_eq!(identifier.as_bytes(), bytes);
        assert_eq!(format!("{identifier:?}"), EXPECTED_DEBUG);
        assert_eq!(format!("{identifier:#?}"), EXPECTED_DEBUG);
        identifier.zeroize();
        // Clearing does not expose the prior or current buffer length.
        assert_eq!(format!("{identifier:?}"), EXPECTED_DEBUG);
    }
}

#[test]
fn algorithm_id_clones_have_independent_clearing_storage() {
    fn require_cleanup<T: ZeroizeOnDrop>() {}
    require_cleanup::<JwaAlgorithmId>();
    let caller_bytes = b"caller-label\0\xff";
    let mut original = JwaAlgorithmId::from_slice(caller_bytes).expect("admitted identifier bytes");
    let mut retained = original.clone();
    assert_eq!(original, retained);
    assert_eq!(retained.as_bytes(), caller_bytes);
    assert_ne!(original.as_bytes().as_ptr(), retained.as_bytes().as_ptr());
    original.zeroize();
    assert!(original.as_bytes().is_empty());
    assert_eq!(retained.as_bytes(), caller_bytes);
    assert_eq!(format!("{retained:?}"), EXPECTED_DEBUG);
    retained.zeroize();
    assert!(retained.as_bytes().is_empty());
}
