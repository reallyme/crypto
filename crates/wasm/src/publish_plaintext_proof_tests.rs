// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::publish_plaintext;
use crypto_core::{authenticate_record, CryptoError};

const TAG_LEN: usize = crypto_core::contract_constants::aes256_gcm::AES_256_GCM_TAG_LENGTH;
const TEXT_LEN: usize = 4;
const RECORD_LEN: usize = TEXT_LEN + TAG_LEN;

#[kani::proof]
#[kani::unwind(17)]
fn failed_open_cannot_invoke_the_javascript_plaintext_copy() {
    let record: [u8; RECORD_LEN] = kani::any();
    let candidate: [u8; TEXT_LEN] = kani::any();
    let writes: [bool; TEXT_LEN] = kani::any();
    let accepts: bool = kani::any();
    let mut invoked = false;
    let opened = authenticate_record::<TAG_LEN>(&record, |staging, _| {
        invoked = true;
        for (index, writes_byte) in writes.into_iter().enumerate() {
            if writes_byte {
                staging[index] = candidate[index];
            }
        }
        if accepts {
            Ok(())
        } else {
            Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
        }
    });

    let mut published = false;
    let outcome = publish_plaintext(opened, |plaintext| {
        published = true;
        assert_eq!(plaintext.len(), TEXT_LEN);
    });
    if invoked {
        assert_eq!(published, accepts);
        if accepts {
            assert_eq!(outcome, Ok(()));
        } else {
            assert_eq!(outcome, Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED));
        }
    } else {
        assert!(!published);
        assert_eq!(outcome, Err(CryptoError::BACKEND_INTERNAL));
    }
    kani::cover!(invoked && accepts && published);
    kani::cover!(invoked && !accepts && writes == [true; TEXT_LEN] && !published);
    kani::cover!(
        invoked
            && !accepts
            && writes != [true; TEXT_LEN]
            && writes != [false; TEXT_LEN]
            && !published
    );
}
