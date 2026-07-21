// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use crypto_core::MacAlgorithm;
use crypto_hmac::{
    authenticate, verify, HmacKey, HmacTag, HMAC_MAX_KEY_LENGTH, HMAC_SHA256_TAG_LENGTH,
    HMAC_SHA384_TAG_LENGTH, HMAC_SHA512_TAG_LENGTH,
};
use hex_literal::hex;

#[test]
fn rfc_4231_hmac_sha256_test_case_1_matches() {
    let key = HmacKey::from_slice(&[0x0b; 20]).unwrap();
    let tag = authenticate(MacAlgorithm::HmacSha256, &key, b"Hi There").unwrap();

    assert_eq!(
        tag.as_bytes(),
        &hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
    assert_eq!(tag.len(), HMAC_SHA256_TAG_LENGTH);
}

#[test]
fn tag_equality_preserves_value_semantics() {
    let expected = [0x42_u8; HMAC_SHA256_TAG_LENGTH];
    let mut different = expected;
    different[HMAC_SHA256_TAG_LENGTH - 1] ^= 0x01;

    let first = HmacTag::from_slice(MacAlgorithm::HmacSha256, &expected).unwrap();
    let second = HmacTag::from_slice(MacAlgorithm::HmacSha256, &expected).unwrap();
    let third = HmacTag::from_slice(MacAlgorithm::HmacSha256, &different).unwrap();

    assert_eq!(first, second);
    assert_ne!(first, third);
}

#[test]
fn rfc_4231_hmac_sha512_test_case_1_matches() {
    let key = HmacKey::from_slice(&[0x0b; 20]).unwrap();
    let tag = authenticate(MacAlgorithm::HmacSha512, &key, b"Hi There").unwrap();

    assert_eq!(
        tag.as_bytes(),
        &hex!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb0"
            "2379f4e2ce4ec2787ad0b30545e17cde"
            "daa833b7d6b8a702038b274eaea3f4e4"
            "be9d914eeb61f1702e696c203a126854"
        )
    );
    assert_eq!(tag.len(), HMAC_SHA512_TAG_LENGTH);
}

#[test]
fn rfc_4231_hmac_sha384_test_case_1_matches() {
    let key = HmacKey::from_slice(&[0x0b; 20]).unwrap();
    let tag = authenticate(MacAlgorithm::HmacSha384, &key, b"Hi There").unwrap();

    assert_eq!(
        tag.as_bytes(),
        &hex!(
            "afd03944d84895626b0825f4ab46907f"
            "15f9dadbe4101ec682aa034c7cebc59c"
            "faea9ea9076ede7f4af152e8b2fa9cb6"
        )
    );
    assert_eq!(tag.len(), HMAC_SHA384_TAG_LENGTH);
}

#[test]
fn verify_accepts_matching_tag_and_rejects_tampering() {
    let key = HmacKey::from_slice(b"Jefe").unwrap();
    let message = b"what do ya want for nothing?";
    for algorithm in [
        MacAlgorithm::HmacSha256,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha512,
    ] {
        let tag = authenticate(algorithm, &key, message).unwrap();
        verify(algorithm, &key, message, tag.as_bytes()).unwrap();

        let mut tampered = tag.clone().into_vec();
        tampered[0] ^= 0x01;
        assert!(verify(algorithm, &key, message, &tampered).is_err());
        assert!(verify(algorithm, &key, b"tampered", tag.as_bytes()).is_err());
    }
}

#[test]
fn wrong_tag_length_is_rejected() {
    let key = HmacKey::from_slice(b"Jefe").unwrap();
    let short_tag = [0u8; HMAC_SHA256_TAG_LENGTH - 1];

    assert!(verify(MacAlgorithm::HmacSha256, &key, b"message", &short_tag).is_err());
    assert!(verify(MacAlgorithm::HmacSha384, &key, b"message", &short_tag).is_err());
    assert!(verify(MacAlgorithm::HmacSha512, &key, b"message", &short_tag).is_err());
}

#[test]
fn empty_and_oversized_keys_are_rejected() {
    assert!(HmacKey::from_slice(&[]).is_err());

    let oversized = vec![0x42u8; HMAC_MAX_KEY_LENGTH + 1];
    assert!(HmacKey::from_slice(&oversized).is_err());
}
