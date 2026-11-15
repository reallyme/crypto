// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use aes_gcm::aead::{
    consts::{U12, U16},
    AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Nonce, Tag, TagPosition,
};
use hpke::{
    aead::Aead,
    danger::streaming_enc::{create_receiver_context, AeadKey, AeadNonce, ExporterSecret},
    inout::InOutBuf,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};

use super::{HpkeReceiverContext, TypedReceiverContext};
use crate::{HpkeError, HPKE_AEAD_NONCE_LEN, HPKE_AEAD_TAG_LEN};

const CIPHERTEXT_LEN: usize = 4;
const RECORD_LEN: usize = CIPHERTEXT_LEN + HPKE_AEAD_TAG_LEN;

// This idealized AEAD recognizes the nonce that sealed a record. Its
// tag encoding is a proof fixture. Real cipher behavior is checked
// separately with independent records through the public contexts.
#[derive(Clone)]
struct NonceBoundAead;

enum ProofAlgorithm {}

impl Aead for ProofAlgorithm {
    type AeadImpl = NonceBoundAead;
    const AEAD_ID: u16 = 0xfffe;
}

impl AeadCore for NonceBoundAead {
    type NonceSize = U12;
    type TagSize = U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl KeySizeUser for NonceBoundAead {
    type KeySize = U16;
}

impl KeyInit for NonceBoundAead {
    fn new(_key: &Key<Self>) -> Self {
        Self
    }
}

impl AeadInOut for NonceBoundAead {
    fn encrypt_inout_detached(
        &self,
        _nonce: &Nonce<Self>,
        _aad: &[u8],
        _buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {
        Err(Error)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        _aad: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        // Overwrite the candidate plaintext before checking authenticity.
        // Even a complete write must stay inside the staging buffer.
        for byte in buffer.get_out() {
            *byte = !*byte;
        }
        if nonce.as_slice() == &tag[..HPKE_AEAD_NONCE_LEN] {
            Ok(())
        } else {
            kani::cover!(
                true,
                "the AEAD rejects after writing the candidate plaintext"
            );
            Err(Error)
        }
    }
}

#[kani::proof]
#[kani::unwind(34)]
fn public_receiver_rejects_nonce_mismatch_without_releasing_plaintext() {
    let base_nonce: [u8; HPKE_AEAD_NONCE_LEN] = kani::any();
    let record: [u8; RECORD_LEN] = kani::any();
    let (_, tag) = record.split_at(CIPHERTEXT_LEN);
    kani::assume(base_nonce.as_slice() != &tag[..HPKE_AEAD_NONCE_LEN]);

    // Supply the established context directly to isolate record processing
    // from KEM and KDF work. At sequence zero the expected record nonce is
    // the base nonce, which ranges over every possible expected nonce.
    let inner = create_receiver_context::<ProofAlgorithm, HkdfSha256, X25519HkdfSha256>(
        &AeadKey::default(),
        AeadNonce(base_nonce.into()),
        ExporterSecret::default(),
    );
    let mut receiver = HpkeReceiverContext {
        backend: Box::new(TypedReceiverContext { inner }),
        authentication_tag_len: HPKE_AEAD_TAG_LEN,
    };

    let result = receiver.open(&[], &record);
    assert!(
        matches!(result, Err(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED)),
        "rejection returns the typed error without plaintext"
    );
    kani::cover!(
        true,
        "the public receiver returns only the authentication error"
    );
}
