// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{PublicKey, SharedKey, combiner};

const FIELD_BYTES: usize = 32;
const LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];
const TRANSCRIPT_BYTES: usize = 4 * FIELD_BYTES + LABEL.len();

/// Observes one arbitrary input byte of the digest transcript. The remaining
/// output bytes carry the offset and the length observed by the fake digest.
pub(super) struct Transcript {
    offset: usize,
    total: usize,
    observed: Option<u8>,
}

impl Transcript {
    pub(super) fn new() -> Self {
        let offset = usize::from(kani::any::<u8>());
        kani::assume(offset < TRANSCRIPT_BYTES);
        Self {
            offset,
            total: 0,
            observed: None,
        }
    }

    pub(super) fn update(&mut self, input: impl AsRef<[u8]>) {
        let bytes = input.as_ref();
        if let Some(value) = self
            .offset
            .checked_sub(self.total)
            .and_then(|i| bytes.get(i))
        {
            assert!(self.observed.replace(*value).is_none());
        }
        self.total = self
            .total
            .checked_add(bytes.len())
            .expect("bounded transcript");
    }

    pub(super) fn finalize(self) -> SharedKey {
        assert_eq!(self.total, TRANSCRIPT_BYTES);
        let mut observation = SharedKey::default();
        observation[..3].copy_from_slice(&[
            u8::try_from(self.offset).expect("bounded transcript offset"),
            self.observed
                .expect("the digest received the selected byte"),
            1, // Establish that the combiner returned the digest's output.
        ]);
        observation
    }
}

#[kani::proof]
#[kani::unwind(40)]
fn x_wing_combiner_hashes_the_prescribed_transcript() {
    let ml_kem: [u8; FIELD_BYTES] = kani::any();
    let x25519: [u8; FIELD_BYTES] = kani::any();
    let ciphertext: [u8; FIELD_BYTES] = kani::any();
    let recipient: [u8; FIELD_BYTES] = kani::any();

    let actual = combiner(
        &ml_kem.into(),
        &x25519,
        &PublicKey::from(ciphertext),
        &PublicKey::from(recipient),
    );
    let offset = usize::from(actual[0]);
    let field = offset / FIELD_BYTES;
    let index = offset % FIELD_BYTES;
    let specification: [&[u8]; 5] = [&ml_kem, &x25519, &ciphertext, &recipient, &LABEL];

    assert_eq!(actual[2], 1);
    assert_eq!(actual[1], specification[field][index]);
    kani::cover!(field == 0, "observe the ML-KEM secret");
    kani::cover!(field == 1, "observe the X25519 secret");
    kani::cover!(field == 2, "observe the X25519 ciphertext");
    kani::cover!(field == 3, "observe the X25519 recipient public key");
    kani::cover!(field == 4, "observe the X-Wing label");
}
