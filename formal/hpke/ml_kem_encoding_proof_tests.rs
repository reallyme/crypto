// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use array::{Array, typenum::U12};

use crate::{DecodedValue, Elem, EncodedPolynomial, Field, byte_decode, byte_encode};

// Same field declaration as the ML-KEM consumer of the locked encoder.
crate::define_field!(MlKemField, u16, u32, u64, 3329);

const COEFFICIENTS_PER_CHUNK: usize = 2;
const BYTES_PER_CHUNK: usize = 3;

fn spec_encode([low, high]: [u16; COEFFICIENTS_PER_CHUNK]) -> [u8; BYTES_PER_CHUNK] {
    // FIPS 203 emits the bits of each 12-bit integer least-significant first.
    let [lo, lo_high] = low.to_le_bytes();
    let [hi, hi_high] = high.to_le_bytes();
    [lo, lo_high | (hi << 4), (hi >> 4) | (hi_high << 4)]
}

fn unpack([first, middle, last]: [u8; BYTES_PER_CHUNK]) -> [u16; COEFFICIENTS_PER_CHUNK] {
    let low = u16::from_le_bytes([first, middle & 0x0f]);
    let high = u16::from(middle >> 4) | (u16::from(last) << 4);
    [low, high]
}

#[kani::proof]
#[kani::unwind(385)]
fn ml_kem_12_bit_encoding_matches_fips_203() {
    let pair: [u16; COEFFICIENTS_PER_CHUNK] = kani::any();
    kani::assume(pair[0] < MlKemField::Q && pair[1] < MlKemField::Q);
    let mut values = DecodedValue::<MlKemField>::default();
    values[..COEFFICIENTS_PER_CHUNK].copy_from_slice(&pair.map(Elem::new));

    let encoded = byte_encode::<MlKemField, U12>(&values);
    assert_eq!(encoded[..BYTES_PER_CHUNK], spec_encode(pair));
}

#[kani::proof]
#[kani::unwind(385)]
fn ml_kem_12_bit_decoding_reduces_as_fips_203() {
    let triplet: [u8; BYTES_PER_CHUNK] = kani::any();
    let mut encoded = EncodedPolynomial::<U12>::default();
    encoded[..BYTES_PER_CHUNK].copy_from_slice(&triplet);

    let decoded: Array<Elem<MlKemField>, _> = byte_decode::<MlKemField, U12>(&encoded);
    assert_eq!(
        decoded[..COEFFICIENTS_PER_CHUNK],
        unpack(triplet).map(|value| Elem::new(value % MlKemField::Q))
    );
}

#[kani::proof]
#[kani::unwind(385)]
fn ml_kem_modulus_check_recognizes_exactly_canonical_chunks() {
    const Q: u16 = 3329;
    let triplet: [u8; BYTES_PER_CHUNK] = kani::any();
    let mut encoded = EncodedPolynomial::<U12>::default();
    encoded[..BYTES_PER_CHUNK].copy_from_slice(&triplet);

    // FIPS 203 compares the original coefficient bytes with their round trip.
    // Encoding and decoding each polynomial process independent 3-byte chunks.
    let decoded = byte_decode::<MlKemField, U12>(&encoded);
    let round_trip = byte_encode::<MlKemField, U12>(&decoded);
    let accepted = round_trip[..BYTES_PER_CHUNK] == triplet;
    let [low, high] = unpack(triplet);
    assert_eq!(accepted, low < Q && high < Q);
    kani::cover!(
        low == Q - 1 && high == Q - 1 && accepted,
        "maximum canonical pair"
    );
    kani::cover!(
        low == Q && high < Q && !accepted,
        "reject the low coefficient"
    );
    kani::cover!(
        low < Q && high == Q && !accepted,
        "reject the high coefficient"
    );
}
