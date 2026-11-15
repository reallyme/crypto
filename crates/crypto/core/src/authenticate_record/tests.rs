// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{authenticate_record, CryptoError};

const TAG_LEN: usize = 16;
const CIPHERTEXT: [u8; 4] = [0x10, 0x20, 0x30, 0x40];
const TAG: [u8; TAG_LEN] = [0x5a; TAG_LEN];
const CANDIDATE: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

#[test]
fn authenticated_record_returns_backend_output_with_tag_removed() -> Result<(), CryptoError> {
    let record = [CIPHERTEXT.as_slice(), TAG.as_slice()].concat();
    let plaintext = authenticate_record::<TAG_LEN>(&record, |output, tag| {
        assert_eq!(output, &CIPHERTEXT);
        assert_eq!(tag, &TAG);
        output.copy_from_slice(&CANDIDATE);
        Ok(())
    })?;

    assert_eq!(plaintext.as_slice(), &CANDIDATE);
    assert_eq!(&record[..CIPHERTEXT.len()], &CIPHERTEXT);
    Ok(())
}

#[test]
fn authentication_failure_discards_a_partially_written_output() {
    let record = [CIPHERTEXT.as_slice(), TAG.as_slice()].concat();
    let mut invoked = false;
    let result = authenticate_record::<TAG_LEN>(&record, |output, _tag| {
        invoked = true;
        output[..2].copy_from_slice(&CANDIDATE[..2]);
        Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
    });

    assert!(invoked);
    assert_eq!(
        result.err(),
        Some(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
    );
    assert_eq!(&record[..CIPHERTEXT.len()], &CIPHERTEXT);
}

#[test]
fn truncated_tags_are_rejected_without_authentication() {
    for length in 0..TAG_LEN {
        let mut invoked = false;
        let result = authenticate_record::<TAG_LEN>(&TAG[..length], |_, _| {
            invoked = true;
            Ok(())
        });
        assert!(!invoked);
        assert_eq!(
            result.err(),
            Some(CryptoError::PRIMITIVE_MALFORMED_CIPHERTEXT)
        );
    }
}

#[test]
fn tag_only_records_still_require_authentication() -> Result<(), CryptoError> {
    let plaintext = authenticate_record::<TAG_LEN>(&TAG, |output, tag| {
        assert!(output.is_empty());
        assert_eq!(tag, &TAG);
        Ok(())
    })?;
    assert!(plaintext.is_empty());

    let result = authenticate_record::<TAG_LEN>(&TAG, |_, _| {
        Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
    });
    assert_eq!(
        result.err(),
        Some(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
    );
    Ok(())
}
