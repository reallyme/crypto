// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{LaneSize, keccak_p};

const WIDTH: usize = 5;
const LANES: usize = WIDTH * WIDTH;
const ROUNDS: usize = 24;
type State = [u64; LANES];

// The FIPS 202 coordinate offsets, indexed by y then x, independent of the
// locked implementation's in-place permutation cycle.
const ROTATION: [[u32; WIDTH]; WIDTH] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

const fn fips_round_constants() -> [u64; ROUNDS] {
    let mut result = [0; ROUNDS];
    let mut register = 1_u8;
    let mut round = 0;
    while round < ROUNDS {
        let mut bit = 0;
        while bit < 7 {
            if register & 1 != 0 {
                result[round] |= 1 << ((1 << bit) - 1);
            }
            let feedback = if register & 0x80 == 0 { 0 } else { 0x71 };
            register = (register << 1) ^ feedback;
            bit += 1;
        }
        round += 1;
    }
    result
}

const CONSTANTS: [u64; ROUNDS] = fips_round_constants();

fn fips_round(input: State, constant: u64) -> State {
    let mut parity = [0; WIDTH];
    for x in 0..WIDTH {
        parity[x] = input[x] ^ input[x + 5] ^ input[x + 10] ^ input[x + 15] ^ input[x + 20];
    }

    let mut lanes = [[0; WIDTH]; WIDTH];
    for y in 0..WIDTH {
        for x in 0..WIDTH {
            let theta = input[y * WIDTH + x]
                ^ parity[(x + 4) % WIDTH]
                ^ parity[(x + 1) % WIDTH].rotate_left(1);
            // Pi maps input (x, y) to output (y, 2x + 3y mod 5).
            lanes[(2 * x + 3 * y) % WIDTH][y] = theta.rotate_left(ROTATION[y][x]);
        }
    }

    let mut output = [0; LANES];
    for (y, row) in lanes.iter().enumerate() {
        for x in 0..WIDTH {
            output[y * WIDTH + x] = row[x] ^ ((!row[(x + 1) % WIDTH]) & row[(x + 2) % WIDTH]);
        }
    }
    output[0] ^= constant;
    output
}

#[kani::proof]
#[kani::unwind(26)]
fn keccak_round_constants_match_fips202_lfsr() {
    let actual = <u64 as LaneSize>::RC;
    assert_eq!(actual.len(), ROUNDS);
    for (index, expected) in CONSTANTS.into_iter().enumerate() {
        assert_eq!(actual[index], expected);
    }
}

#[kani::proof]
#[kani::unwind(26)]
fn portable_keccak_p1600_one_round_matches_fips202() {
    let input: State = kani::any();
    let mut actual = input;
    keccak_p::<u64, 1>(&mut actual);
    // FIPS 202 KECCAK-p uses the final nr rounds of KECCAK-f.
    let expected = fips_round(input, CONSTANTS[ROUNDS - 1]);
    for (index, lane) in actual.into_iter().enumerate() {
        assert_eq!(lane, expected[index]);
    }
}
