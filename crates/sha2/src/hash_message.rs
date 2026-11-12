// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use sha2::{
    block_api::{compress512, Sha512VarCore},
    digest::{array::Array, block_api::Buffer},
};
use zeroize::Zeroizing;

// FIPS 180-4 sections 5.3.4 and 5.3.5. Compression and padding use the existing
// implementations. Direct fixed-size serialization avoids CtOutWrapper's
// unguarded full-result array, including SHA-384's discarded state words.
pub(crate) const SHA384_INITIAL_STATE: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];
pub(crate) const SHA512_INITIAL_STATE: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];
const BLOCK_BITS: u128 = 1024;
const BYTE_BITS: u128 = 8;

pub(crate) fn hash<const OUTPUT_LEN: usize>(
    message: &[u8],
    initial_state: [u64; 8],
    output: &mut [u8; OUTPUT_LEN],
) {
    let mut state = Zeroizing::new(initial_state);
    let mut buffer = Zeroizing::new(Buffer::<Sha512VarCore>::default());
    let mut bit_length = 0_u128;
    buffer.digest_blocks(message, |blocks| {
        for _ in blocks {
            bit_length = bit_length.wrapping_add(BLOCK_BITS);
        }
        compress512(&mut state, Array::cast_slice_to_core(blocks));
    });
    for _ in buffer.get_data() {
        bit_length = bit_length.wrapping_add(BYTE_BITS);
    }
    buffer.len128_padding_be(bit_length, |block| {
        compress512(&mut state, core::slice::from_ref(&block.0));
    });
    for (destination, word) in output
        .as_chunks_mut::<{ size_of::<u64>() }>()
        .0
        .iter_mut()
        .zip(state.iter())
    {
        let encoded = Zeroizing::new(word.to_be_bytes());
        destination.copy_from_slice(encoded.as_ref());
    }
}
