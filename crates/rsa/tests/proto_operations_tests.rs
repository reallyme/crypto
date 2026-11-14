// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema/native RSA operation parity and ownership regressions.

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used)]
// Establish clearing generated fixture owners before populating their fields.
#![allow(clippy::field_reassign_with_default)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use buffa::{EnumValue, Enumeration, Message, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoNativeVerificationResult, CryptoRsaPssParams, CryptoRsaPssVerifyRequest,
    CryptoRsaPublicKeyDerEncodingIdentifier, CryptoRsaPublicRepresentativesRequest,
    CryptoRsaPublicRepresentativesResult, CryptoVerificationStatus, RsaHashAlgorithm,
};
use crypto_rsa::proto_operations::{PublicRepresentativesInputs, RsaPssVerifyInputs};
use crypto_rsa::{
    verify_rsa_pss, RsaHash, RsaPssParams, RsaPublicKeyDerEncoding, RsaPublicRepresentatives,
};
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Existing immutable verification fixtures from rsa_tests.rs.
const PUBLIC_KEY_DER: &str = "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJtVqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkhJ88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB";
const MESSAGE: &str = "UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg";
const PSS_SHA1: &str = "rM_td9L0bEnDyo8_7wxbYy2R7b-td3ZB69TFvaoFfm3VLBBELVOpYjHzcW3SKoiKkW56qQ8ZhOfCbWabUVvEmi85l0cf1fjX9Uk1n7tLDRjZwQyBGR3LS5JmOI5TpXZCb9d_wzS4F_wo2x_HTix_fkX7aysINa8RBABlkE9SlofwRWpgn7GTGnnc59WPVKuUUfnNEchm683eyUzi78Mfv5sKLgP7odUYMtMsaQsAN25MYrkmfoRKS-RzQKSV0m7NdGawT2JfPVYV-Q5ZwUtgj_n5FmoCqU7N-Rs2OJMojEvbFfMaAdFFDnyK8pblY0Nt-4epH8U6dPriTdtFa2g_Tw";
const PSS_SHA256: &str = "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEzNPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWTaJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw";
const PSS_SHA384: &str = "MEnKhv7atsfMZOREi-0Ta-jDTPNHW6U1lz0_WgIkvWLJ2fohqgy2nwyBBfU-JtSZrVEaPEbIElu15F0NKHyoNUGU1WY_bwZVVSPCKWIHjbrQwK8whZw3H8NCP9G5zRJhzpFtIYBdG6H4oOzIYHSNvk7_-suOgiaTsSg0eg-ZxXypXYCGBp-mE1iJ4hRYnOVv-_Sbje00qbFCGL6WwP7Jxnucp11p4Plli25GBkggZu1gTGEhGRnU2j9NTZKxbT2Q-MTZ3mTuQohsVvUNMfF6r2ns9FEQIrsApAu2bryJcPVZkulkyBmVTW2XopOFXI-MlkQpmekoLB7ZHP6enlefBQ";
const PSS_SHA512: &str = "rzU-aGeM1kEp6mvkQgaJ9myGNXyGtP6r18iBfZNEXf0viVvOjL_ebVE2nD3MUEtiPbxD7TAH-4JXfD-STG3BaGDjH0uVu5KCgSPjKRcskEZuOSzhmJ485fP5oc8yRnrl9lIy-RD0ItX5NWU6g40otuC7LmsrH2vWB2KoOKeWQFgCQD_KP8mssSWVuhwml-S3egN8-S6cprMbwHvJsn1KDpWn_pp0gM9FWyNoHqivekcgGJKz0iVcLzHUbxI5lhj51djBuw32bNrU7jB8dQwf847J9ZDr4cAz_vbP5oCTdXOibPG2J0joYR4mpbRgeernoZGxIf44p7HJX75J-WxE0Q";

fn decode(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value)
        .expect("fixed public RSA fixture")
}

fn pss_request(params: RsaPssParams, signature: &[u8]) -> CryptoRsaPssVerifyRequest {
    let mut output = CryptoRsaPssVerifyRequest::default();
    assert!(output
        .public_key_der
        .extend_from_slice(&decode(PUBLIC_KEY_DER))
        .is_ok());
    output.public_key_encoding =
        CryptoRsaPublicKeyDerEncodingIdentifier::from(RsaPublicKeyDerEncoding::Pkcs1).encoding;
    output.params =
        MessageField::some(CryptoRsaPssParams::try_from(&params).expect("fixed PSS params"));
    assert!(output.message.extend_from_slice(&decode(MESSAGE)).is_ok());
    assert!(output.signature.extend_from_slice(signature).is_ok());
    output
}

fn sha256_params() -> RsaPssParams {
    RsaPssParams {
        message_hash: RsaHash::Sha256,
        mgf1_hash: RsaHash::Sha256,
        salt_len: 32,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepresentativeCase {
    pkcs1: String,
    spki: String,
    signature: String,
    ordinary: String,
    complement: String,
}

fn representatives() -> Vec<RepresentativeCase> {
    serde_json::from_str(include_str!("representatives.json")).expect("fixed integer answers")
}

fn hex_bytes(text: &str) -> Vec<u8> {
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("fixture hex"), 16)
                .expect("fixture byte")
        })
        .collect()
}

fn representative_request(
    case: &RepresentativeCase,
    encoding: RsaPublicKeyDerEncoding,
) -> CryptoRsaPublicRepresentativesRequest {
    let mut output = CryptoRsaPublicRepresentativesRequest::default();
    assert!(output
        .public_key_der
        .extend_from_slice(&hex_bytes(match encoding {
            RsaPublicKeyDerEncoding::Pkcs1 => &case.pkcs1,
            RsaPublicKeyDerEncoding::Spki => &case.spki,
        }))
        .is_ok());
    output.public_key_encoding = CryptoRsaPublicKeyDerEncodingIdentifier::from(encoding).encoding;
    assert!(output
        .signature
        .extend_from_slice(&hex_bytes(&case.signature))
        .is_ok());
    output
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn representative_contract_preserves_all_84_integer_answers_and_both_der_encodings(
) -> Result<(), CryptoError> {
    let cases = representatives();
    assert_eq!(cases.len(), 84);
    for case in cases {
        for encoding in [
            RsaPublicKeyDerEncoding::Pkcs1,
            RsaPublicKeyDerEncoding::Spki,
        ] {
            let request = representative_request(&case, encoding);
            let inputs = PublicRepresentativesInputs::try_from(&request)?;
            assert_eq!(inputs.encoding(), encoding);
            assert_eq!(inputs.public_key_der(), request.public_key_der.as_slice());
            assert_eq!(inputs.signature(), request.signature.as_slice());
            let native = inputs.recover()?;
            let output = CryptoRsaPublicRepresentativesResult::try_from(&native)?;
            assert_eq!(output.ordinary, hex_bytes(&case.ordinary));
            assert_eq!(output.complement, hex_bytes(&case.complement));
            assert_eq!(output.ordinary.len(), request.signature.len());
            assert_eq!(output.complement.len(), request.signature.len());
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn representative_contract_preserves_range_width_and_key_errors() {
    let case = representatives().pop().expect("nonempty fixed corpus");
    let mut request = representative_request(&case, RsaPublicKeyDerEncoding::Spki);
    let width = request.signature.len();
    request.signature.clear();
    assert_eq!(
        PublicRepresentativesInputs::try_from(&request)
            .and_then(|inputs| inputs.recover())
            .err(),
        Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    assert!(request.signature.resize(width, 0xff).is_ok());
    assert_eq!(
        PublicRepresentativesInputs::try_from(&request)
            .and_then(|inputs| inputs.recover())
            .err(),
        Some(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    request.public_key_der.clear();
    assert_eq!(
        PublicRepresentativesInputs::try_from(&request)
            .and_then(|inputs| inputs.recover())
            .err(),
        Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    );
    assert!(request
        .public_key_der
        .resize(
            crypto_rsa::RSA_PUBLIC_KEY_DER_MAX_LEN
                .checked_add(1)
                .expect("bounded fixture"),
            0,
        )
        .is_ok());
    assert_eq!(
        PublicRepresentativesInputs::try_from(&request)
            .and_then(|inputs| inputs.recover())
            .err(),
        Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pss_contract_verifies_existing_sha1_and_sha2_known_answers() -> Result<(), CryptoError> {
    for (hash, salt_len, signature) in [
        (RsaHash::Sha1, 20, PSS_SHA1),
        (RsaHash::Sha256, 32, PSS_SHA256),
        (RsaHash::Sha384, 48, PSS_SHA384),
        (RsaHash::Sha512, 64, PSS_SHA512),
    ] {
        let params = RsaPssParams {
            message_hash: hash,
            mgf1_hash: hash,
            salt_len,
        };
        let request = pss_request(params, &decode(signature));
        let inputs = RsaPssVerifyInputs::try_from(&request)?;
        assert_eq!(inputs.params(), params);
        assert_eq!(inputs.public_key_der(), request.public_key_der.as_slice());
        assert_eq!(inputs.message(), request.message.as_slice());
        assert_eq!(inputs.signature(), request.signature.as_slice());
        assert_eq!(
            inputs.verify()?.status.as_known(),
            Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID)
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pss_contract_does_not_collapse_independent_hashes_or_explicit_salt_lengths(
) -> Result<(), CryptoError> {
    let signature = decode(PSS_SHA256);
    for message_hash in RsaHashAlgorithm::values()
        .iter()
        .filter(|value| value.to_i32() != 0)
    {
        for mgf1_hash in RsaHashAlgorithm::values()
            .iter()
            .filter(|value| value.to_i32() != 0)
        {
            for salt_length in [0, 32, u32::MAX] {
                let mut request = pss_request(sha256_params(), &signature);
                let params = CryptoRsaPssParams {
                    message_hash: (*message_hash).into(),
                    mgf1_hash: (*mgf1_hash).into(),
                    salt_length: Some(salt_length),
                };
                let expected = RsaPssParams::try_from(&params)?;
                request.params = MessageField::some(params);
                let inputs = RsaPssVerifyInputs::try_from(&request)?;
                assert_eq!(inputs.params(), expected);
                let native = verify_rsa_pss(
                    inputs.public_key_der(),
                    inputs.encoding(),
                    expected,
                    inputs.message(),
                    inputs.signature(),
                );
                let adapted = inputs.verify().map(|_| ());
                assert_eq!(adapted, native);
                if expected == sha256_params() {
                    assert_eq!(adapted, Ok(()));
                } else {
                    assert_eq!(adapted, Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE));
                }
            }
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pss_contract_keeps_native_invalid_key_and_invalid_signature_distinct() {
    let mut request = pss_request(sha256_params(), &decode(PSS_SHA256));
    assert!(request.message.extend_from_slice(&[0, 0xff, 0x80]).is_ok());
    assert_eq!(
        RsaPssVerifyInputs::try_from(&request)
            .and_then(|inputs| inputs.verify())
            .err(),
        Some(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    request.signature.clear();
    assert_eq!(
        RsaPssVerifyInputs::try_from(&request)
            .and_then(|inputs| inputs.verify())
            .err(),
        Some(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    request.public_key_der.clear();
    assert_eq!(
        RsaPssVerifyInputs::try_from(&request)
            .and_then(|inputs| inputs.verify())
            .err(),
        Some(CryptoError::PRIMITIVE_INVALID_KEY)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn new_requests_reject_missing_unknown_and_modified_metadata() -> Result<(), CryptoError> {
    let mut request = pss_request(sha256_params(), &decode(PSS_SHA256));
    request.params = MessageField::none();
    assert_eq!(
        RsaPssVerifyInputs::try_from(&request).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut params = CryptoRsaPssParams::try_from(&sha256_params())?;
    params.salt_length = None;
    request.params = MessageField::some(params);
    assert_eq!(
        RsaPssVerifyInputs::try_from(&request).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let params = CryptoRsaPssParams::try_from(&sha256_params())?;
    let mut modified_child = params.encode_to_vec();
    modified_child.extend_from_slice(&[0xa0, 0x06, 0x01]);
    request.params = MessageField::some(params);
    let mut modified = request.encode_to_vec();
    // The duplicate child retains protobuf merge semantics but the unknown
    // modifier must fail admission before any operation uses the message.
    buffa::encoding::encode_varint((3u64 << 3) | 2, &mut modified);
    buffa::encoding::encode_varint(
        u64::try_from(modified_child.len()).unwrap_or(u64::MAX),
        &mut modified,
    );
    modified.extend_from_slice(&modified_child);
    assert!(crypto_proto::wire::decode_protobuf::<CryptoRsaPssVerifyRequest>(&modified).is_err());
    request = pss_request(sha256_params(), &decode(PSS_SHA256));
    assert_unknown_wire(&request, &[0xa0, 0x06, 0x01]);
    let case = representatives().pop().expect("fixed fixture");
    for invalid in [0, -1, 99, i32::MAX] {
        let mut request = pss_request(sha256_params(), &decode(PSS_SHA256));
        request.public_key_encoding = EnumValue::from(invalid);
        assert_eq!(
            RsaPssVerifyInputs::try_from(&request).err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
        let mut request = representative_request(&case, RsaPublicKeyDerEncoding::Pkcs1);
        request.public_key_encoding = EnumValue::from(invalid);
        assert_eq!(
            PublicRepresentativesInputs::try_from(&request).err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let request = representative_request(&case, RsaPublicKeyDerEncoding::Pkcs1);
    assert_unknown_wire(&request, &[0xa0, 0x06, 0x01]);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn copied_inputs_and_outputs_have_independent_clearing_ownership() -> Result<(), CryptoError> {
    fn requires_owner<T: ZeroizeOnDrop>() {}
    requires_owner::<CryptoRsaPublicRepresentativesRequest>();
    requires_owner::<CryptoRsaPublicRepresentativesResult>();
    requires_owner::<CryptoRsaPssVerifyRequest>();
    requires_owner::<CryptoNativeVerificationResult>();
    requires_owner::<RsaPublicRepresentatives>();
    requires_owner::<PublicRepresentativesInputs>();
    requires_owner::<RsaPssVerifyInputs>();
    let request = pss_request(sha256_params(), &decode(PSS_SHA256));
    let mut inputs = RsaPssVerifyInputs::try_from(&request)?;
    inputs.zeroize();
    assert!(inputs.public_key_der().is_empty());
    assert!(inputs.message().is_empty());
    assert!(inputs.signature().is_empty());
    assert!(!request.public_key_der.is_empty());
    assert!(!request.message.is_empty());
    let case = representatives().pop().expect("fixed fixture");
    let request = representative_request(&case, RsaPublicKeyDerEncoding::Pkcs1);
    let mut inputs = PublicRepresentativesInputs::try_from(&request)?;
    let output = inputs.result()?;
    inputs.zeroize();
    assert!(inputs.public_key_der().is_empty());
    assert!(inputs.signature().is_empty());
    assert!(!output.ordinary.is_empty());
    assert!(!output.complement.is_empty());
    assert_eq!(
        inputs.recover().err(),
        Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn impossible_rsa_sizes_are_rejected_before_copied_input_ownership() {
    let case = representatives().pop().expect("fixed valid key");
    let mut representative = representative_request(&case, RsaPublicKeyDerEncoding::Spki);
    let mut pss = pss_request(sha256_params(), &decode(PSS_SHA256));
    let key_overflow = crypto_rsa::RSA_PUBLIC_KEY_DER_MAX_LEN
        .checked_add(1)
        .expect("bounded public key fixture");
    for length in [0, key_overflow] {
        assert!(representative.public_key_der.resize(length, 0).is_ok());
        assert!(pss.public_key_der.resize(length, 0).is_ok());
        assert_eq!(
            PublicRepresentativesInputs::try_from(&representative).err(),
            Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY),
        );
        assert_eq!(
            RsaPssVerifyInputs::try_from(&pss).err(),
            Some(CryptoError::PRIMITIVE_INVALID_KEY),
        );
    }
    let bits_per_octet = usize::try_from(u8::BITS).expect("fixed byte width");
    let minimum = crypto_rsa::RSA_MIN_MODULUS_BITS.div_ceil(bits_per_octet);
    for length in [
        0,
        minimum.checked_sub(1).expect("minimum signature"),
        crypto_rsa::RSA_SIGNATURE_MAX_LEN
            .checked_add(1)
            .expect("maximum signature"),
    ] {
        let mut representative = representative_request(&case, RsaPublicKeyDerEncoding::Spki);
        assert!(representative.signature.resize(length, 0).is_ok());
        assert_eq!(
            PublicRepresentativesInputs::try_from(&representative).err(),
            Some(CryptoError::PRIMITIVE_INVALID_LENGTH),
        );
        let mut pss = pss_request(sha256_params(), &decode(PSS_SHA256));
        assert!(pss.signature.resize(length, 0).is_ok());
        assert_eq!(
            RsaPssVerifyInputs::try_from(&pss).err(),
            Some(CryptoError::PRIMITIVE_INVALID_SIGNATURE),
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_bounded_der_keeps_precedence_over_impossible_signature_width() {
    let case = representatives().pop().expect("fixed key");
    for signature_length in [
        0,
        crypto_rsa::RSA_SIGNATURE_MAX_LEN
            .checked_add(1)
            .expect("bounded signature"),
    ] {
        let mut representative = representative_request(&case, RsaPublicKeyDerEncoding::Spki);
        representative.public_key_der.clear();
        assert!(representative
            .public_key_der
            .extend_from_slice(&[0x30, 0])
            .is_ok());
        assert!(representative.signature.resize(signature_length, 0).is_ok());
        let expected = crypto_rsa::rsa_public_representatives(
            &representative.public_key_der,
            RsaPublicKeyDerEncoding::Spki,
            &representative.signature,
        )
        .err();
        assert_eq!(expected, Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY));
        assert_eq!(
            PublicRepresentativesInputs::try_from(&representative).err(),
            expected
        );
        let mut pss = pss_request(sha256_params(), &decode(PSS_SHA256));
        pss.public_key_der.clear();
        assert!(pss.public_key_der.extend_from_slice(&[0x30, 0]).is_ok());
        assert!(pss.signature.resize(signature_length, 0).is_ok());
        let expected = verify_rsa_pss(
            &pss.public_key_der,
            RsaPublicKeyDerEncoding::Pkcs1,
            sha256_params(),
            &pss.message,
            &pss.signature,
        )
        .err();
        assert_eq!(expected, Some(CryptoError::PRIMITIVE_INVALID_KEY));
        assert_eq!(RsaPssVerifyInputs::try_from(&pss).err(), expected);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn admission_keeps_native_width_endpoints_and_does_not_apply_key_caps_to_messages(
) -> Result<(), CryptoError> {
    let mut minimum_seen = false;
    let mut maximum_seen = false;
    let bits_per_octet = usize::try_from(u8::BITS).expect("fixed byte width");
    let minimum = crypto_rsa::RSA_MIN_MODULUS_BITS.div_ceil(bits_per_octet);
    for case in representatives() {
        let representative = representative_request(&case, RsaPublicKeyDerEncoding::Spki);
        if representative.signature.len() == minimum
            || representative.signature.len() == crypto_rsa::RSA_SIGNATURE_MAX_LEN
        {
            let inputs = PublicRepresentativesInputs::try_from(&representative)?;
            let output = inputs.result()?;
            assert_eq!(output.ordinary, hex_bytes(&case.ordinary));
            minimum_seen |= representative.signature.len() == minimum;
            maximum_seen |= representative.signature.len() == crypto_rsa::RSA_SIGNATURE_MAX_LEN;
        }
    }
    assert!(minimum_seen);
    assert!(maximum_seen);
    let mut pss = pss_request(sha256_params(), &decode(PSS_SHA256));
    let message_length = crypto_rsa::RSA_PUBLIC_KEY_DER_MAX_LEN
        .checked_add(crypto_rsa::RSA_SIGNATURE_MAX_LEN)
        .and_then(|length| length.checked_add(1))
        .expect("bounded independent message fixture");
    assert!(pss.message.resize(message_length, 0xff).is_ok());
    let inputs = RsaPssVerifyInputs::try_from(&pss)?;
    assert_eq!(inputs.message(), pss.message.as_slice());
    assert_eq!(
        inputs.verify().err(),
        Some(CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    Ok(())
}

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
