// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;

use crate::{
    AesKw, Error, InnerInit,
    cipher::{
        Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
        BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser,
        ParBlocksSizeUser,
        inout::InOut,
        typenum::{U1, U16},
    },
};

const SEMIBLOCK_BYTES: usize = 8;
const KEY_SEMIBLOCKS: usize = 2;
const CALLS: usize = 6 * KEY_SEMIBLOCKS;
const RFC_IV: u64 = 0xa6a6_a6a6_a6a6_a6a6;

#[derive(Clone, Copy)]
struct Registers {
    integrity: u64,
    key: [u64; KEY_SEMIBLOCKS],
    calls: usize,
}

struct RoundTranscript(Cell<Registers>);

impl RoundTranscript {
    fn new(integrity: u64, key: [u64; KEY_SEMIBLOCKS]) -> Self {
        Self(Cell::new(Registers {
            integrity,
            key,
            calls: 0,
        }))
    }

    fn step(&self, mut block: InOut<'_, '_, Block<Self>>, wrapping: bool) {
        let mut state = self.0.get();
        assert!(state.calls < CALLS);
        // RFC 3394 indexes a single sequence of AES calls with t ascending
        // for wrap and descending for unwrap. Use wordwise XOR as the oracle.
        let counter = if wrapping {
            state.calls + 1
        } else {
            CALLS - state.calls
        };
        let register = (counter - 1) % KEY_SEMIBLOCKS;
        let counter = u64::try_from(counter).expect("bounded RFC round counter");
        let expected_high = if wrapping {
            state.integrity
        } else {
            state.integrity ^ counter
        };
        assert_eq!(
            block.get_in()[..SEMIBLOCK_BYTES],
            expected_high.to_be_bytes()
        );
        assert_eq!(
            block.get_in()[SEMIBLOCK_BYTES..],
            state.key[register].to_be_bytes()
        );

        // Each invocation can return any two words. This proves the mode's
        // data dependencies without evaluating or assuming a specific cipher.
        let [high, low]: [u64; 2] = kani::any();
        let output = block.get_out();
        output[..SEMIBLOCK_BYTES].copy_from_slice(&high.to_be_bytes());
        output[SEMIBLOCK_BYTES..].copy_from_slice(&low.to_be_bytes());
        state.integrity = if wrapping { high ^ counter } else { high };
        state.key[register] = low;
        state.calls += 1;
        self.0.set(state);
    }

    fn finished(&self) -> Registers {
        let state = self.0.get();
        assert_eq!(state.calls, CALLS);
        state
    }
}

impl BlockSizeUser for RoundTranscript {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for RoundTranscript {
    type ParBlocksSize = U1;
}

impl BlockCipherEncBackend for RoundTranscript {
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        self.step(block, true);
    }
}

impl BlockCipherDecBackend for RoundTranscript {
    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        self.step(block, false);
    }
}

impl BlockCipherEncrypt for RoundTranscript {
    fn encrypt_with_backend(&self, closure: impl BlockCipherEncClosure<BlockSize = U16>) {
        closure.call(self);
    }
}

impl BlockCipherDecrypt for RoundTranscript {
    fn decrypt_with_backend(&self, closure: impl BlockCipherDecClosure<BlockSize = U16>) {
        closure.call(self);
    }
}

type KeyBytes = [u8; KEY_SEMIBLOCKS * SEMIBLOCK_BYTES];
type WrappedBytes = [u8; (KEY_SEMIBLOCKS + 1) * SEMIBLOCK_BYTES];

fn key_bytes(words: [u64; KEY_SEMIBLOCKS]) -> KeyBytes {
    let mut bytes = [0; KEY_SEMIBLOCKS * SEMIBLOCK_BYTES];
    bytes[..SEMIBLOCK_BYTES].copy_from_slice(&words[0].to_be_bytes());
    bytes[SEMIBLOCK_BYTES..].copy_from_slice(&words[1].to_be_bytes());
    bytes
}

#[kani::proof]
#[kani::unwind(25)]
fn aes_kw_locked_wrap_matches_rfc3394_round_transcript() {
    let input: [u64; KEY_SEMIBLOCKS] = kani::any();
    let transcript = RoundTranscript::new(RFC_IV, input);
    let kw = AesKw::inner_init(&transcript);
    let mut output: WrappedBytes = kani::any();

    let wrapped = kw
        .wrap_key(&key_bytes(input), &mut output)
        .expect("valid wrap sizes");
    let state = transcript.finished();
    assert_eq!(wrapped[..SEMIBLOCK_BYTES], state.integrity.to_be_bytes());
    assert_eq!(wrapped[SEMIBLOCK_BYTES..], key_bytes(state.key));
}

#[kani::proof]
#[kani::unwind(25)]
fn aes_kw_locked_unwrap_matches_rfc3394_round_transcript() {
    let leading: u64 = kani::any();
    let input: [u64; KEY_SEMIBLOCKS] = kani::any();
    let transcript = RoundTranscript::new(leading, input);
    let kw = AesKw::inner_init(&transcript);
    let mut wrapped: WrappedBytes = [0; (KEY_SEMIBLOCKS + 1) * SEMIBLOCK_BYTES];
    wrapped[..SEMIBLOCK_BYTES].copy_from_slice(&leading.to_be_bytes());
    wrapped[SEMIBLOCK_BYTES..].copy_from_slice(&key_bytes(input));
    let mut output: KeyBytes = kani::any();

    let result = kw.unwrap_key(&wrapped, &mut output);
    let state = transcript.finished();
    if state.integrity == RFC_IV {
        assert_eq!(
            result.expect("the correct IV must admit the key"),
            key_bytes(state.key)
        );
    } else {
        assert_eq!(result.err(), Some(Error::IntegrityCheckFailed));
        assert_eq!(output, [0; KEY_SEMIBLOCKS * SEMIBLOCK_BYTES]);
    }
    kani::cover!(state.integrity == RFC_IV, "recover the required IV");
    kani::cover!(
        state.integrity != RFC_IV,
        "wipe decoded data after a wrong IV"
    );
}
