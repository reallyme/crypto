// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![cfg(feature = "prime-groups")]

use crypto_core::CryptoError;
use reallyme_crypto::prime_groups::PrimeGroup;

// Independently calculated from the published RFC 5114 p/q values with integer
// division. The production validator does not generate its own expected inputs.
const CASES: &[(PrimeGroup, &str)] = &[
    (
        PrimeGroup::Rfc5114Dh1024_160,
        concat!(
            "b8ebe0f59149e18dba11a1ea8ce50df2c2543fd2d2f3d34e8e7197c6ff466866f150c55e3e5b0534",
            "e618f0a94d0a4cca5ddd87765d2e34502f004c63c89df1bb59ca2a0af5128c86b503ca48f4edf08b",
            "4768ff2eadfbf4256abc08a2f1a67eb763e9b10ae246aecdaeda30d0",
        ),
    ),
    (
        PrimeGroup::Rfc5114Dh2048_224,
        concat!(
            "0159d531ebfb397c23b76b18005b9d03570e91210c86657b51faa2b97e6f3ed4521f79f51081c2d4",
            "c2389591c98beb2689be050f910a76c2bdfe9c8e5f5cee51dc4ca83bdaee721f3c64a2800be05daa",
            "80d99eea3d17750fda9b1bcc1f538e7bf8147908dc101e3d4a180cde963d25697d336d06622560de",
            "0072fe75ed403dfec86dba165c609b0de873a6efd6337e6fdda0af817c26feb59b405178437f56ed",
            "238f6025c6812804205bcdc0169c076509f45530d0cf2e4e60d8f20ee54fb4afdb6524ca9a743fa6",
            "16ea909f372e0040c9c94ea90fbd414c63ec541d49d65f521e2d11716a",
        ),
    ),
    (
        PrimeGroup::Rfc5114Dh2048_256,
        concat!(
            "f65b7ea7706034a28a29b9436af161bbf3632483671c60aee9b1a6a496fff904fcb09731b6c6e16b",
            "551cec2c063910b04e40795d4beb474db762e28cc923ae40fdbaf05bf7501d0314c3cbe4bad7329d",
            "d473bdf441e7b8b387b402cd0be7dc534fa6d3c039bdad133f59dc899fd570a667c453d08150a35c",
            "f5e845087bd9acfa8333343375e8ee52965a84c699c59dfef852efb96023bef0ffb2f99c53ac2d94",
            "cd2969764698b8dde401da6aa6bdb3b03b5506d287090f8e852c05ec0bdb3c0c4fbec1a4ab9fe141",
            "e8a7c9eadb17d335921b673615a7fc0c92384946b9ab6452",
        ),
    ),
];

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn canonical_builtin_dh_metadata_accepts_each_optional_combination() -> Result<(), CryptoError> {
    for &(group, expected) in CASES {
        let j = hex::decode(expected).unwrap();
        let p = group.modulus();
        let g = group.standard_generator_encoding();
        for q in [None, Some(group.order())] {
            for cofactor in [None, Some(j.as_slice())] {
                group.validate_dh_parameters(p, g, q, cofactor)?;
            }
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_and_mismatched_metadata_never_admits_a_domain() {
    for &(group, expected) in CASES {
        let j = hex::decode(expected).unwrap();
        let originals = [
            group.modulus(),
            group.standard_generator_encoding(),
            group.order(),
            j.as_slice(),
        ];
        let maximums = [
            group.field_len(),
            group.field_len(),
            group.scalar_len(),
            group.field_len(),
        ];
        for field in 0..originals.len() {
            let mut padded = vec![0];
            padded.extend_from_slice(originals[field]);
            let oversized = vec![1; maximums[field].checked_add(1).unwrap()];
            let mut changed = originals[field].to_vec();
            *changed.last_mut().unwrap() ^= 1;
            for (invalid, expected) in [
                (&[][..], CryptoError::PRIMITIVE_INVALID_LENGTH),
                (&[0][..], CryptoError::PRIMITIVE_INVALID_PARAMETER),
                (oversized.as_slice(), CryptoError::PRIMITIVE_INVALID_LENGTH),
                (changed.as_slice(), CryptoError::PRIMITIVE_INVALID_PARAMETER),
            ] {
                let mut values = originals;
                values[field] = invalid;
                assert_eq!(
                    group.validate_dh_parameters(
                        values[0],
                        values[1],
                        Some(values[2]),
                        Some(values[3])
                    ),
                    Err(expected)
                );
            }
            // Padding that exceeds an exact-width field is rejected by its bound;
            // a shorter cofactor with an extra leading zero is noncanonical.
            let expected = if padded.len() > maximums[field] {
                CryptoError::PRIMITIVE_INVALID_LENGTH
            } else {
                CryptoError::PRIMITIVE_INVALID_PARAMETER
            };
            let mut values = originals;
            values[field] = &padded;
            assert_eq!(
                group.validate_dh_parameters(
                    values[0],
                    values[1],
                    Some(values[2]),
                    Some(values[3])
                ),
                Err(expected)
            );
        }
        assert_eq!(
            group.validate_dh_parameters(
                group.modulus(),
                group.standard_generator_encoding(),
                None,
                Some(&[1])
            ),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
        assert_eq!(
            PrimeGroup::NistP256.validate_dh_parameters(
                group.modulus(),
                group.standard_generator_encoding(),
                None,
                None
            ),
            Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
    let first = PrimeGroup::Rfc5114Dh2048_224;
    let other = PrimeGroup::Rfc5114Dh2048_256;
    assert_eq!(
        first.validate_dh_parameters(
            other.modulus(),
            other.standard_generator_encoding(),
            None,
            None
        ),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
}

#[cfg(feature = "operation-response")]
mod schema {
    use super::{CryptoError, PrimeGroup, CASES};
    use buffa::{Message, MessageField};
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        CryptoPrimeGroupDhParametersValidationRequest,
        CryptoPrimeGroupDhParametersValidationResult, CryptoPrimeGroupIdentifier,
        PrimeGroup as ProtoGroup,
    };
    use reallyme_crypto::prime_groups::contract;
    use zeroize::Zeroizing;

    fn request(
        group: PrimeGroup,
        q: Option<Vec<u8>>,
        j: Option<Vec<u8>>,
    ) -> CryptoPrimeGroupDhParametersValidationRequest {
        CryptoPrimeGroupDhParametersValidationRequest {
            group: MessageField::some(CryptoPrimeGroupIdentifier {
                group: ProtoGroup::from(group).into(),
                __buffa_unknown_fields: Default::default(),
            }),
            p: group.modulus().to_vec(),
            g: group.standard_generator_encoding().to_vec(),
            q,
            j,
            __buffa_unknown_fields: Default::default(),
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn native_and_generated_validation_preserve_optional_presence_and_errors() {
        for &(group, expected) in CASES {
            let cofactor = hex::decode(expected).unwrap();
            for q in [
                None,
                Some(Vec::new()),
                Some(group.order().to_vec()),
                Some(vec![1]),
            ] {
                for j in [
                    None,
                    Some(Vec::new()),
                    Some(cofactor.clone()),
                    Some(vec![1]),
                ] {
                    let value = request(group, q.clone(), j);
                    let wire = Zeroizing::new(value.encode_to_vec());
                    let decoded =
                        CryptoPrimeGroupDhParametersValidationRequest::decode_from_slice(&wire)
                            .unwrap();
                    assert_eq!(decoded.q, value.q);
                    assert_eq!(decoded.j, value.j);
                    let native = group.validate_dh_parameters(
                        &decoded.p,
                        &decoded.g,
                        decoded.q.as_deref(),
                        decoded.j.as_deref(),
                    );
                    let adapted = contract::validate_dh_parameters(&decoded);
                    assert_eq!(native.as_ref().err(), adapted.as_ref().err());
                    if native.is_ok() {
                        let result = adapted.unwrap();
                        assert_eq!(
                            PrimeGroup::try_from(result.group.as_option().unwrap()).unwrap(),
                            group
                        );
                    }
                }
            }
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn missing_unknown_and_unspecified_selection_fails_closed() {
        let group = PrimeGroup::Rfc5114Dh1024_160;
        let mut value = request(group, None, None);
        value.group = MessageField::none();
        assert_eq!(
            contract::validate_dh_parameters(&value).err(),
            Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
        );
        for selected in [0, 9999] {
            let mut value = request(group, None, None);
            value.group.as_option_mut().unwrap().group = selected.into();
            assert_eq!(
                contract::validate_dh_parameters(&value).err(),
                Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            );
        }
        let mut value = request(group, None, None);
        value.merge_from_slice(&[0xf8, 0x07, 1]).unwrap();
        assert_eq!(
            contract::validate_dh_parameters(&value).err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
        let mut value = request(group, None, None);
        value
            .group
            .as_option_mut()
            .unwrap()
            .merge_from_slice(&[0x10, 1])
            .unwrap();
        assert_eq!(
            contract::validate_dh_parameters(&value).err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn parameter_request_and_result_retain_clearing_owners() {
        fn clearing<T: zeroize::ZeroizeOnDrop>() {}
        clearing::<CryptoPrimeGroupDhParametersValidationRequest>();
        clearing::<CryptoPrimeGroupDhParametersValidationResult>();
    }
}
