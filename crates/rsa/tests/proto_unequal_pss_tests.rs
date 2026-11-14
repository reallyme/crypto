// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Primary unequal-hash RSA-PSS vectors preserve independent parameter semantics.

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used)]

use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoRsaPssParams, CryptoRsaPssVerifyRequest, CryptoVerificationStatus,
    RsaPublicKeyDerEncoding as ProtoEncoding,
};
use crypto_rsa::proto_operations::RsaPssVerifyInputs;
use crypto_rsa::{verify_rsa_pss, RsaPssParams, RsaPublicKeyDerEncoding};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    case_id: u32,
    public_key_der_hex: String,
    message_hex: String,
    signature_hex: String,
    params: CryptoRsaPssParams,
}

fn cases() -> Vec<Case> {
    serde_json::from_str(include_str!("data/rsa_pss_unequal_hashes.json"))
        .expect("pinned public Wycheproof cases")
}

fn bytes(text: &str) -> Zeroizing<Vec<u8>> {
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    Zeroizing::new(
        pairs
            .iter()
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("fixed hex"), 16)
                    .expect("fixed public vector byte")
            })
            .collect(),
    )
}

fn request(case: &Case, params: RsaPssParams) -> CryptoRsaPssVerifyRequest {
    let mut output = CryptoRsaPssVerifyRequest::default();
    assert!(output
        .public_key_der
        .extend_from_slice(&bytes(&case.public_key_der_hex))
        .is_ok());
    output.public_key_encoding = ProtoEncoding::RSA_PUBLIC_KEY_DER_ENCODING_SPKI.into();
    output.params =
        MessageField::some(CryptoRsaPssParams::try_from(&params).expect("fixed params"));
    assert!(output
        .message
        .extend_from_slice(&bytes(&case.message_hex))
        .is_ok());
    assert!(output
        .signature
        .extend_from_slice(&bytes(&case.signature_hex))
        .is_ok());
    output
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn all_existing_unequal_hash_pairings_verify_with_zero_and_nonzero_salt() -> Result<(), CryptoError>
{
    let cases = cases();
    assert_eq!(cases.len(), 24);
    for case in cases {
        let params = RsaPssParams::try_from(&case.params)?;
        assert_ne!(params.message_hash, params.mgf1_hash);
        assert!(params.salt_len == 0 || params.salt_len == 32);
        let request = request(&case, params);
        assert_eq!(
            verify_rsa_pss(
                &request.public_key_der,
                RsaPublicKeyDerEncoding::Spki,
                params,
                &request.message,
                &request.signature,
            ),
            Ok(()),
            "published valid case {}",
            case.case_id,
        );
        let inputs = RsaPssVerifyInputs::try_from(&request)?;
        assert_eq!(inputs.params(), params);
        assert_eq!(inputs.message(), request.message.as_slice());
        assert_eq!(inputs.signature(), request.signature.as_slice());
        assert_eq!(inputs.public_key_der(), request.public_key_der.as_slice());
        assert_eq!(
            inputs.verify()?.status.as_known(),
            Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID)
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn collapsing_hashes_changing_salt_or_message_cannot_verify_the_published_signatures(
) -> Result<(), CryptoError> {
    for case in cases() {
        let params = RsaPssParams::try_from(&case.params)?;
        for changed in [
            RsaPssParams {
                mgf1_hash: params.message_hash,
                ..params
            },
            RsaPssParams {
                message_hash: params.mgf1_hash,
                ..params
            },
            RsaPssParams {
                salt_len: params
                    .salt_len
                    .checked_add(1)
                    .expect("bounded fixture salt"),
                ..params
            },
        ] {
            let request = request(&case, changed);
            assert_eq!(
                RsaPssVerifyInputs::try_from(&request)?.verify().err(),
                Some(CryptoError::PRIMITIVE_INVALID_SIGNATURE),
                "parameter change in published case {}",
                case.case_id,
            );
        }
        let mut request = request(&case, params);
        assert!(request.message.push(0).is_ok());
        assert_eq!(
            RsaPssVerifyInputs::try_from(&request)?.verify().err(),
            Some(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
        );
    }
    Ok(())
}
