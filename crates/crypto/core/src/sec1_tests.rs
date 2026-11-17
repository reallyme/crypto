// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::has_standard_sec1_encoding;

#[test]
fn standard_sec1_shapes_require_the_matching_tag_and_exact_width() {
    // P-256 and secp256k1 have identical encoding widths. Point validity
    // belongs to each curve parser, so these bytes exercise only admission.
    for (compressed_length, uncompressed_length) in [(33, 65), (49, 97), (67, 133)] {
        assert!(!has_standard_sec1_encoding(
            &[],
            compressed_length,
            uncompressed_length
        ));
        for prefix in 0_u8..=u8::MAX {
            for (length, expected) in [
                (compressed_length, matches!(prefix, 0x02 | 0x03)),
                (uncompressed_length, prefix == 0x04),
                (1, false),
            ] {
                let bytes = vec![prefix; length];
                assert_eq!(
                    has_standard_sec1_encoding(&bytes, compressed_length, uncompressed_length),
                    expected
                );
            }
        }
        for (length, prefix) in [(compressed_length, 0x02), (uncompressed_length, 0x04)] {
            let mut bytes = vec![prefix; length];
            bytes.pop();
            assert!(!has_standard_sec1_encoding(
                &bytes,
                compressed_length,
                uncompressed_length
            ));
            bytes.push(0);
            bytes.push(0);
            assert!(!has_standard_sec1_encoding(
                &bytes,
                compressed_length,
                uncompressed_length
            ));
        }
    }
}
