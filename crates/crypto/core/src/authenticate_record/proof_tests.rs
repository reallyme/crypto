// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{authenticate_record, CryptoError};

const TAG_LEN: usize = crate::contract_constants::aes256_gcm::AES_256_GCM_TAG_LENGTH;
const CIPHERTEXT_LEN: usize = 4;
const RECORD_LEN: usize = CIPHERTEXT_LEN + TAG_LEN;
const _: () = {
    assert!(TAG_LEN == crate::contract_constants::aes256_gcm_siv::AES_256_GCM_SIV_TAG_LENGTH);
    assert!(TAG_LEN == crate::contract_constants::chacha20_poly1305::CHACHA20_POLY1305_TAG_LENGTH);
    assert!(TAG_LEN == crate::contract_constants::hpke::HPKE_AEAD_TAG_LEN);
    assert!(TAG_LEN == crate::contract_constants::hpke_base_p256::TAG_LEN);
};

#[kani::proof]
#[kani::unwind(17)]
fn plaintext_release_requires_success_after_any_bounded_backend_write() {
    let record: [u8; RECORD_LEN] = kani::any();
    let candidate: [u8; CIPHERTEXT_LEN] = kani::any();
    let written: [bool; CIPHERTEXT_LEN] = kani::any();
    let accepts: bool = kani::any();
    let mut invoked = false;

    let outcome = authenticate_record::<TAG_LEN>(&record, |output, tag| {
        invoked = true;
        assert_eq!(output, &record[..CIPHERTEXT_LEN]);
        assert_eq!(tag, &record[CIPHERTEXT_LEN..]);
        for (index, write) in written.into_iter().enumerate() {
            if write {
                output[index] = candidate[index];
            }
        }
        if accepts {
            Ok(())
        } else {
            Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
        }
    });

    kani::cover!(invoked && accepts, "the success path is reachable");
    kani::cover!(
        invoked && !accepts && written == [true; CIPHERTEXT_LEN],
        "authentication failure after a complete buffer write is reachable"
    );
    kani::cover!(
        invoked
            && !accepts
            && written != [false; CIPHERTEXT_LEN]
            && written != [true; CIPHERTEXT_LEN],
        "authentication failure after a partial buffer write is reachable"
    );
    match outcome {
        Ok(plaintext) => {
            assert!(invoked && accepts);
            assert_eq!(plaintext.len(), CIPHERTEXT_LEN);
            for (index, write) in written.into_iter().enumerate() {
                let expected = if write {
                    candidate[index]
                } else {
                    record[index]
                };
                assert_eq!(plaintext[index], expected);
            }
        }
        Err(error) if invoked => {
            assert!(!accepts);
            assert_eq!(error, CryptoError::PRIMITIVE_AUTHENTICATION_FAILED);
        }
        Err(error) => assert_eq!(error, CryptoError::BACKEND_INTERNAL),
    }
}

#[kani::proof]
#[kani::unwind(12)]
fn short_tags_cannot_reach_the_backend() {
    let bytes: [u8; TAG_LEN] = kani::any();
    let len: usize = kani::any();
    kani::assume(len < TAG_LEN);
    let mut invoked = false;

    let outcome = authenticate_record::<TAG_LEN>(&bytes[..len], |_, _| {
        invoked = true;
        Ok(())
    });

    assert!(!invoked);
    assert_eq!(
        outcome.err(),
        Some(CryptoError::PRIMITIVE_MALFORMED_CIPHERTEXT)
    );
}
