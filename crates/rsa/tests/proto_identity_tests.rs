// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema-derived identity parity, rejected modifiers and stable metadata bytes.

#![cfg(feature = "proto")]
#![allow(missing_docs)]

use buffa::{Enumeration, Message};
use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoRsaHashIdentifier, CryptoRsaPublicKeyDerEncodingIdentifier, RsaHashAlgorithm,
    RsaPublicKeyDerEncoding as ProtoRsaEncoding,
};
use crypto_rsa::{RsaHash, RsaPublicKeyDerEncoding};

#[test]
fn rsa_hash_parity_covers_every_generated_identity_and_exact_wire_bytes() {
    for &value in RsaHashAlgorithm::values() {
        let identifier = CryptoRsaHashIdentifier {
            hash: value.into(),
            __buffa_unknown_fields: Default::default(),
        };
        let expected: Option<(RsaHash, &[u8])> = match value {
            RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA1 => Some((RsaHash::Sha1, &[0x08, 0x64])),
            RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA256 => {
                Some((RsaHash::Sha256, &[0x08, 0xc8, 0x01]))
            }
            RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA384 => {
                Some((RsaHash::Sha384, &[0x08, 0xd2, 0x01]))
            }
            RsaHashAlgorithm::RSA_HASH_ALGORITHM_SHA512 => {
                Some((RsaHash::Sha512, &[0x08, 0xdc, 0x01]))
            }
            _ => None,
        };
        match expected {
            Some((native, wire)) => {
                assert_eq!(RsaHash::try_from(&identifier), Ok(native));
                let reverse = CryptoRsaHashIdentifier::from(native);
                assert_eq!(reverse.hash.as_known(), Some(value));
                assert!(reverse.__buffa_unknown_fields.is_empty());
                assert_eq!(reverse.encode_to_vec().as_slice(), wire);
            }
            None => {
                assert_eq!(
                    value.to_i32(),
                    0,
                    "every registered identity needs an explicit native mapping"
                );
                assert_eq!(
                    RsaHash::try_from(&identifier),
                    Err(UnsupportedProtoAlgorithm)
                );
            }
        }
    }
}

#[test]
fn rsa_hash_rejects_zero_negative_and_unknown_numbers() {
    for number in [i32::MIN, -1, 0, 99_999, i32::MAX] {
        let identifier = CryptoRsaHashIdentifier {
            hash: number.into(),
            __buffa_unknown_fields: Default::default(),
        };
        assert_eq!(
            RsaHash::try_from(&identifier),
            Err(UnsupportedProtoAlgorithm)
        );
    }
}

#[test]
fn rsa_hash_rejects_retained_unknown_modifiers() -> Result<(), buffa::DecodeError> {
    let mut identifier = CryptoRsaHashIdentifier::from(RsaHash::Sha1);
    // Unknown field 100 is public test data, not an accepted policy modifier.
    identifier.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert!(!identifier.__buffa_unknown_fields.is_empty());
    assert_eq!(
        RsaHash::try_from(&identifier),
        Err(UnsupportedProtoAlgorithm)
    );
    Ok(())
}

#[test]
fn rsa_der_encoding_parity_covers_every_generated_identity_and_exact_wire_bytes() {
    for &value in ProtoRsaEncoding::values() {
        let identifier = CryptoRsaPublicKeyDerEncodingIdentifier {
            encoding: value.into(),
            __buffa_unknown_fields: Default::default(),
        };
        let expected: Option<(RsaPublicKeyDerEncoding, &[u8])> = match value {
            ProtoRsaEncoding::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1 => {
                Some((RsaPublicKeyDerEncoding::Pkcs1, &[0x08, 0x01]))
            }
            ProtoRsaEncoding::RSA_PUBLIC_KEY_DER_ENCODING_SPKI => {
                Some((RsaPublicKeyDerEncoding::Spki, &[0x08, 0x02]))
            }
            _ => None,
        };
        match expected {
            Some((native, wire)) => {
                assert_eq!(RsaPublicKeyDerEncoding::try_from(&identifier), Ok(native));
                let reverse = CryptoRsaPublicKeyDerEncodingIdentifier::from(native);
                assert_eq!(reverse.encoding.as_known(), Some(value));
                assert!(reverse.__buffa_unknown_fields.is_empty());
                assert_eq!(reverse.encode_to_vec().as_slice(), wire);
            }
            None => {
                assert_eq!(
                    value.to_i32(),
                    0,
                    "every registered identity needs an explicit native mapping"
                );
                assert_eq!(
                    RsaPublicKeyDerEncoding::try_from(&identifier),
                    Err(UnsupportedProtoAlgorithm)
                );
            }
        }
    }
}

#[test]
fn rsa_der_encoding_rejects_zero_negative_and_unknown_numbers() {
    for number in [i32::MIN, -1, 0, 99_999, i32::MAX] {
        let identifier = CryptoRsaPublicKeyDerEncodingIdentifier {
            encoding: number.into(),
            __buffa_unknown_fields: Default::default(),
        };
        assert_eq!(
            RsaPublicKeyDerEncoding::try_from(&identifier),
            Err(UnsupportedProtoAlgorithm)
        );
    }
}

#[test]
fn rsa_der_encoding_rejects_retained_unknown_modifiers() -> Result<(), buffa::DecodeError> {
    let mut identifier =
        CryptoRsaPublicKeyDerEncodingIdentifier::from(RsaPublicKeyDerEncoding::Pkcs1);
    // Unknown field 100 is public test data, not an accepted policy modifier.
    identifier.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert!(!identifier.__buffa_unknown_fields.is_empty());
    assert_eq!(
        RsaPublicKeyDerEncoding::try_from(&identifier),
        Err(UnsupportedProtoAlgorithm)
    );
    Ok(())
}

#[test]
fn decoded_metadata_owners_clear_retained_unknown_storage_on_drop() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoRsaHashIdentifier>();
    require_cleanup::<CryptoRsaPublicKeyDerEncodingIdentifier>();
}

#[test]
fn schema_metadata_does_not_renumber_existing_rsa_ffi_identifiers() {
    for (hash, expected) in [
        (RsaHash::Sha1, 1),
        (RsaHash::Sha256, 2),
        (RsaHash::Sha384, 3),
        (RsaHash::Sha512, 4),
    ] {
        assert_eq!(hash.ffi_id(), expected);
        assert_eq!(RsaHash::from_ffi_id(expected), Some(hash));
    }
    for (encoding, expected) in [
        (RsaPublicKeyDerEncoding::Pkcs1, 1),
        (RsaPublicKeyDerEncoding::Spki, 2),
    ] {
        assert_eq!(encoding.ffi_id(), expected);
        assert_eq!(
            RsaPublicKeyDerEncoding::from_ffi_id(expected),
            Some(encoding)
        );
    }
    for invalid in [0, u32::MAX] {
        assert_eq!(RsaHash::from_ffi_id(invalid), None);
        assert_eq!(RsaPublicKeyDerEncoding::from_ffi_id(invalid), None);
    }
}
