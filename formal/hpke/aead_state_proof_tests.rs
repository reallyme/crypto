// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// This module is appended to the locked backend's aead.rs in a temporary copy.
// It needs private access to initialize a context near sequence exhaustion.

use aead::{
    AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Nonce, Tag, TagPosition,
    consts::{U12, U16},
};

use super::{
    Aead, AeadCtx, AeadCtxR, AeadCtxS, AeadKey, AeadNonce, AeadTag, ExporterSecret, HpkeError,
    InOutBuf, Seq, increment_seq, mix_nonce,
};
use crate::{kdf::HkdfSha256, kem::X25519HkdfSha256};

const NONCE_LEN: usize = 12;
const NONCE_PADDING: usize = size_of::<u128>() - NONCE_LEN;
const UNTOUCHED: u8 = 0;
const AEAD_CALLED: u8 = 1;

#[kani::proof]
fn sequence_increment_is_exact_until_exhaustion() {
    let seq: u64 = kani::any();
    let next = increment_seq(&Seq(seq));

    if seq == u64::MAX {
        assert!(next.is_none());
    } else {
        assert_eq!(next.map(|value| value.0), Some(seq + 1));
    }
}

fn check_nonce_mixing<A>()
where
    A: Aead,
    A::AeadImpl: AeadCore<NonceSize = U12>,
{
    let bytes: [u8; NONCE_LEN] = kani::any();
    let seq: u64 = kani::any();
    let other_seq: u64 = kani::any();
    let base = AeadNonce::<A>(bytes.into());

    let actual = mix_nonce(&base, &Seq(seq));
    let other = mix_nonce(&base, &Seq(other_seq));
    assert_eq!(actual.0.as_slice(), &specified_nonce(bytes, seq));
    assert_eq!(actual.0 == other.0, seq == other_seq);
}

fn specified_nonce(base: [u8; NONCE_LEN], seq: u64) -> [u8; NONCE_LEN] {
    // Use integer XOR as the specification. The backend instead writes the
    // sequence into a nonce-sized buffer, then XORs the byte iterators.
    let mut padded = [0_u8; size_of::<u128>()];
    padded[NONCE_PADDING..].copy_from_slice(&base);
    let mixed = (u128::from_be_bytes(padded) ^ u128::from(seq)).to_be_bytes();
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&mixed[NONCE_PADDING..]);
    nonce
}

#[kani::proof]
#[kani::unwind(17)]
fn aes128_gcm_nonce_matches_rfc9180_and_is_injective() {
    check_nonce_mixing::<super::AesGcm128>();
}

#[kani::proof]
#[kani::unwind(17)]
fn aes256_gcm_nonce_matches_rfc9180_and_is_injective() {
    check_nonce_mixing::<super::AesGcm256>();
}

#[kani::proof]
#[kani::unwind(17)]
fn chacha20_poly1305_nonce_matches_rfc9180_and_is_injective() {
    check_nonce_mixing::<super::ChaCha20Poly1305>();
}

// The AEAD boundary exposes success or failure and whether it was called.
// Write before deciding the outcome so exhausted contexts must prove they
// leave the caller's output untouched even if the AEAD would write on error.
#[derive(Clone)]
struct ObservedAead {
    accepts: bool,
    expected_nonce: [u8; NONCE_LEN],
}

struct ObservedAlgorithm;

impl Aead for ObservedAlgorithm {
    type AeadImpl = ObservedAead;
    const AEAD_ID: u16 = 0xfffe;
}

impl AeadCore for ObservedAead {
    type NonceSize = U12;
    type TagSize = U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl KeySizeUser for ObservedAead {
    type KeySize = U16;
}

impl KeyInit for ObservedAead {
    fn new(_key: &Key<Self>) -> Self {
        Self {
            accepts: false,
            expected_nonce: [0; NONCE_LEN],
        }
    }
}

impl AeadInOut for ObservedAead {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        _aad: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> aead::Result<Tag<Self>> {
        assert_eq!(nonce.as_slice(), &self.expected_nonce);
        buffer.get_out().fill(AEAD_CALLED);
        if self.accepts {
            Ok(Tag::<Self>::default())
        } else {
            Err(Error)
        }
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        _aad: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        assert_eq!(nonce.as_slice(), &self.expected_nonce);
        buffer.get_out().fill(AEAD_CALLED);
        // An ideal record for a different nonce is authentic only at that
        // nonce. Write first to keep the error path realistic.
        if self.accepts && nonce.as_slice() == &tag[..NONCE_LEN] {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

type ObservedContext = AeadCtx<ObservedAlgorithm, HkdfSha256, X25519HkdfSha256>;

fn tag_for_nonce(nonce: [u8; NONCE_LEN]) -> AeadTag<ObservedAlgorithm> {
    let mut tag = AeadTag::default();
    tag.0[..NONCE_LEN].copy_from_slice(&nonce);
    tag
}

fn context(seq: u64, exhausted: bool, accepts: bool) -> ObservedContext {
    let base_nonce: [u8; NONCE_LEN] = kani::any();
    let mut context = ObservedContext::new(
        &AeadKey::default(),
        AeadNonce(base_nonce.into()),
        ExporterSecret::default(),
    );
    assert_eq!(context.seq.0, 0);
    assert!(!context.overflowed);
    context.seq = Seq(seq);
    context.overflowed = exhausted;
    context.encryptor.accepts = accepts;
    context.encryptor.expected_nonce = specified_nonce(base_nonce, seq);
    context
}

fn check_transition(
    context: ObservedContext,
    backend_error: HpkeError,
    operate: impl Fn(ObservedContext, &mut [u8]) -> (ObservedContext, Result<(), HpkeError>),
) {
    let seq = context.seq.0;
    let exhausted = context.overflowed;
    let accepts = context.encryptor.accepts;
    let mut byte = [UNTOUCHED];
    let (context, result) = operate(context, &mut byte);

    if exhausted {
        assert_eq!(result, Err(HpkeError::MessageLimitReached));
        assert_eq!(byte, [UNTOUCHED]);
        assert_eq!(context.seq.0, seq);
        assert!(context.overflowed);
    } else if !accepts {
        assert_eq!(result, Err(backend_error));
        assert_eq!(byte, [AEAD_CALLED]);
        assert_eq!(context.seq.0, seq);
        assert!(!context.overflowed);
    } else {
        assert_eq!(result, Ok(()));
        assert_eq!(byte, [AEAD_CALLED]);
        if seq == u64::MAX {
            assert_eq!(context.seq.0, seq);
            assert!(context.overflowed);
            let mut next_byte = [UNTOUCHED];
            let (context, result) = operate(context, &mut next_byte);
            assert_eq!(result, Err(HpkeError::MessageLimitReached));
            assert_eq!(next_byte, [UNTOUCHED]);
            assert_eq!(context.seq.0, seq);
            assert!(context.overflowed);
        } else {
            assert_eq!(context.seq.0, seq + 1);
            assert!(!context.overflowed);
        }
    }
}

#[kani::proof]
// Leave room for the backend's fixed-size array initialization and clearing.
#[kani::unwind(65)]
fn sender_advances_only_on_success_and_exhaustion_is_terminal() {
    let context = context(kani::any(), kani::any(), kani::any());
    check_transition(context, HpkeError::SealError, |context, buffer| {
        let mut sender = AeadCtxS::from(context);
        let result = sender.seal_inout_detached(buffer.into(), &[]).map(|_| ());
        (sender.0, result)
    });
}

#[kani::proof]
#[kani::unwind(65)]
fn receiver_advances_only_on_success_and_exhaustion_is_terminal() {
    let context = context(kani::any(), kani::any(), kani::any());
    check_transition(context, HpkeError::OpenError, |context, buffer| {
        let tag = tag_for_nonce(context.encryptor.expected_nonce);
        let mut receiver = AeadCtxR::from(context);
        let result = receiver.open_inout_detached(buffer.into(), &[], &tag);
        (receiver.0, result)
    });
}

#[kani::proof]
#[kani::unwind(65)]
fn receiver_rejects_a_different_sequence_and_accepts_the_expected_record() {
    let seq: u64 = kani::any();
    let offered_seq: u64 = kani::any();
    kani::assume(offered_seq != seq);
    let mut receiver = AeadCtxR::from(context(seq, false, true));
    let mut base_nonce = [0_u8; NONCE_LEN];
    base_nonce.copy_from_slice(receiver.0.base_nonce.0.as_slice());
    let valid_tag = tag_for_nonce(specified_nonce(base_nonce, seq));
    let invalid_tag = tag_for_nonce(specified_nonce(base_nonce, offered_seq));

    // The AEAD checks the same independently specified nonce on both
    // calls. Only the offered record changes between attempts. Use fresh
    // scratch space because the backend can write on either outcome.
    let mut rejected = [UNTOUCHED];
    let first = receiver.open_inout_detached(rejected.as_mut_slice().into(), &[], &invalid_tag);
    assert_eq!(first, Err(HpkeError::OpenError));
    assert_eq!(rejected, [AEAD_CALLED]);
    assert_eq!(receiver.0.seq.0, seq);
    assert!(!receiver.0.overflowed);
    kani::cover!(offered_seq < seq, "a duplicate or stale record is rejected");
    kani::cover!(
        offered_seq > seq,
        "a skipped or reordered record is rejected"
    );

    let mut retried = [UNTOUCHED];
    let retry = receiver.open_inout_detached(retried.as_mut_slice().into(), &[], &valid_tag);
    assert_eq!(retry, Ok(()));
    assert_eq!(retried, [AEAD_CALLED]);
    if let Some(next) = seq.checked_add(1) {
        assert_eq!(receiver.0.seq.0, next);
        assert!(!receiver.0.overflowed);
        kani::cover!(true, "retry succeeds before the last nonce");
    } else {
        assert_eq!(receiver.0.seq.0, seq);
        assert!(receiver.0.overflowed);
        kani::cover!(true, "retry succeeds on the last nonce");

        // The record that just authenticated is still valid at this
        // nonce. Exhaustion must reject it without entering the AEAD.
        let mut after_exhaustion = [UNTOUCHED];
        let result =
            receiver.open_inout_detached(after_exhaustion.as_mut_slice().into(), &[], &valid_tag);
        assert_eq!(result, Err(HpkeError::MessageLimitReached));
        assert_eq!(after_exhaustion, [UNTOUCHED]);
        assert_eq!(receiver.0.seq.0, seq);
        assert!(receiver.0.overflowed);
    }
}
