// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::derive_private_key_from_candidates;
use crate::HPKE_SECP256K1_PRIVATE_KEY_LEN;
use zeroize::Zeroizing;

#[test]
fn exhausted_derivation_reduces_the_final_candidate_before_wiping() {
    // n and n+1 are both rejected scalars. Reduction into [1,n) maps them to
    // 2 and 3, respectively. A prematurely wiped candidate instead produces 1.
    let mut rejected = Zeroizing::new([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ]);
    for (last_byte, expected_scalar) in [(0x41, 2), (0x42, 3)] {
        rejected[HPKE_SECP256K1_PRIVATE_KEY_LEN - 1] = last_byte;
        let mut calls = 0_u16;
        let key = derive_private_key_from_candidates(|counter, output| {
            assert_eq!(u16::from(counter), calls);
            assert!(output.iter().all(|byte| *byte == 0));
            calls += 1;
            // Earlier candidates differ so the test also proves the final
            // candidate, rather than an earlier rejected value, is reduced.
            if counter == u8::MAX {
                output.copy_from_slice(rejected.as_slice());
            } else {
                output.fill(0xff);
            }
            Ok(())
        });
        assert_eq!(calls, 256);
        let mut expected = Zeroizing::new([0_u8; HPKE_SECP256K1_PRIVATE_KEY_LEN]);
        expected[HPKE_SECP256K1_PRIVATE_KEY_LEN - 1] = expected_scalar;
        let actual = Zeroizing::new(key.to_bytes());
        assert_eq!(actual.as_slice(), expected.as_slice());
    }
}

#[test]
fn rejection_sampling_stops_at_the_first_valid_candidate() {
    for accepted_counter in [0_u8, 1, u8::MAX] {
        let mut calls = 0_u16;
        let key = derive_private_key_from_candidates(|counter, output| {
            assert!(output.iter().all(|byte| *byte == 0));
            calls += 1;
            if counter == accepted_counter {
                output[HPKE_SECP256K1_PRIVATE_KEY_LEN - 1] = 7;
            } else {
                output.fill(0xff);
            }
            Ok(())
        });
        assert_eq!(calls, u16::from(accepted_counter) + 1);
        let actual = Zeroizing::new(key.to_bytes());
        assert!(actual[..HPKE_SECP256K1_PRIVATE_KEY_LEN - 1]
            .iter()
            .all(|byte| *byte == 0));
        assert_eq!(actual[HPKE_SECP256K1_PRIVATE_KEY_LEN - 1], 7);
    }
}
