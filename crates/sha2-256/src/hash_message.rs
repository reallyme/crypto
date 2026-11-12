// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use sha2::{
    block_api::{compress256, Sha256VarCore},
    digest::{array::Array, block_api::Buffer},
};
use zeroize::Zeroizing;

use crate::SHA2_256_DIGEST_LENGTH;

// FIPS 180-4 section 5.3.3. The compression and padding implementations remain
// those of sha2/block-buffer; only fixed-output ownership is handled here.
const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const BLOCK_BITS: u64 = 512;
const BYTE_BITS: u64 = 8;

pub(crate) fn hash(message: &[u8], output: &mut [u8; SHA2_256_DIGEST_LENGTH]) {
    let mut state = Zeroizing::new(INITIAL_STATE);
    let mut buffer = Zeroizing::new(Buffer::<Sha256VarCore>::default());
    let mut bit_length = 0_u64;
    buffer.digest_blocks(message, |blocks| {
        // SHA-2's encoded length is a modular bit counter, not a buffer size.
        // Counting typed blocks avoids converting an attacker-controlled usize.
        for _ in blocks {
            bit_length = bit_length.wrapping_add(BLOCK_BITS);
        }
        compress256(&mut state, Array::cast_slice_to_core(blocks));
    });
    for _ in buffer.get_data() {
        bit_length = bit_length.wrapping_add(BYTE_BITS);
    }
    buffer.len64_padding_be(bit_length, |block| {
        compress256(&mut state, core::slice::from_ref(&block.0));
    });
    for (destination, word) in output
        .as_chunks_mut::<{ size_of::<u32>() }>()
        .0
        .iter_mut()
        .zip(state.iter())
    {
        let encoded = Zeroizing::new(word.to_be_bytes());
        destination.copy_from_slice(encoded.as_ref());
    }
}
