// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{authenticate_record, P256BaseError};

const RECORD_BYTES: usize = 4;

#[kani::proof]
#[kani::unwind(12)]
fn plaintext_is_published_only_on_successful_authentication() {
    let ciphertext: [u8; RECORD_BYTES] = kani::any();
    let candidate: [u8; RECORD_BYTES] = kani::any();
    let success: bool = kani::any();
    let mut invoked = false;

    let outcome = authenticate_record(&ciphertext, |output| {
        invoked = true;
        assert_eq!(output, &ciphertext);
        output.copy_from_slice(&candidate);
        if success {
            Ok(())
        } else {
            Err(hpke::HpkeError::OpenError)
        }
    });

    // Allocation may fail before authentication and must return a typed
    // backend error. Exercise both outcomes once the backend is called.
    kani::cover!(invoked && success, "successful authentication is reachable");
    kani::cover!(invoked && !success, "authentication failure is reachable");
    match outcome {
        Ok(plaintext) => {
            assert!(invoked && success);
            assert_eq!(plaintext.as_slice(), &candidate);
        }
        Err(error) if invoked => {
            assert!(!success);
            assert_eq!(error, P256BaseError::PRIMITIVE_AUTHENTICATION_FAILED);
        }
        Err(error) => assert_eq!(error, P256BaseError::BACKEND_INTERNAL),
    }
}
