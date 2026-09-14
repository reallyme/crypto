// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{HpkeReceiverContext, ReceiverContextBackend};
use crate::error::HpkeError;

struct FixedPlaintext(Vec<u8>);

impl ReceiverContextBackend for FixedPlaintext {
    fn open(&mut self, _aad: &[u8], _ciphertext: &[u8]) -> Result<Vec<u8>, hpke::HpkeError> {
        Ok(core::mem::take(&mut self.0))
    }
}

#[test]
fn receiver_preserves_plaintext_length_validation() -> Result<(), HpkeError> {
    const TAG_LENGTH: usize = 16;
    for length in [0, 2, 3, 4] {
        let mut context = HpkeReceiverContext {
            backend: Box::new(FixedPlaintext(vec![0xa5; length])),
            authentication_tag_len: TAG_LENGTH,
        };
        let result = context.open(&[], &[0; 19]);
        if length == 3 {
            assert_eq!(result?.plaintext.as_slice(), &[0xa5; 3]);
        } else {
            assert!(matches!(result, Err(HpkeError::OpenFailed)));
        }
    }
    Ok(())
}
