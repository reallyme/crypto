// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    encode_kem_suite_id, HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256, HPKE_KEM_DHKEM_X448_HKDF_SHA512,
    HPKE_KEM_ML_KEM_1024_P384, HPKE_KEM_ML_KEM_512,
};

#[test]
fn registered_kem_contexts_preserve_prefix_width_and_big_endian_identity() {
    assert_eq!(encode_kem_suite_id(HPKE_KEM_ML_KEM_512), *b"KEM\x00\x40");
    assert_eq!(
        encode_kem_suite_id(HPKE_KEM_ML_KEM_1024_P384),
        *b"KEM\x00\x51"
    );
    assert_eq!(
        encode_kem_suite_id(HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256),
        *b"KEM\x00\x16"
    );
    assert_eq!(
        encode_kem_suite_id(HPKE_KEM_DHKEM_X448_HKDF_SHA512),
        *b"KEM\x00\x21"
    );
    assert_eq!(encode_kem_suite_id(0x1234), *b"KEM\x12\x34");
}
