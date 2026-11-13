// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional byte presence and clearing generated owner boundaries.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{DecodeError, DecodeOptions, ExtensionSet, Message};
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoArgon2FixedDeriveRequest, CryptoHkdfDeriveInputs, CryptoHkdfDomainKey32Request,
    CryptoHkdfDomainTag, CryptoHkdfExpandSha384Request, CryptoHkdfExtractSha384Request,
    CryptoHkdfExtractSha384Result, CryptoJwkOptions, CryptoRsaPssParams, PublicAkpJwk, PublicEcJwk,
    PublicJwk, PublicJwkDocument, PublicJwks, PublicOkpJwk,
};

#[test]
fn generated_options_and_transitive_wrappers_have_clearing_ownership() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoRsaPssParams>();
    require_cleanup::<CryptoArgon2FixedDeriveRequest>();
    require_cleanup::<CryptoHkdfDomainTag>();
    require_cleanup::<CryptoHkdfDeriveInputs>();
    require_cleanup::<CryptoHkdfExtractSha384Request>();
    require_cleanup::<CryptoHkdfExtractSha384Result>();
    require_cleanup::<CryptoHkdfExpandSha384Request>();
    require_cleanup::<CryptoHkdfDomainKey32Request>();
    require_cleanup::<CryptoJwkOptions>();
    require_cleanup::<PublicEcJwk>();
    require_cleanup::<PublicOkpJwk>();
    require_cleanup::<PublicAkpJwk>();
    require_cleanup::<PublicJwk>();
    require_cleanup::<PublicJwks>();
    require_cleanup::<PublicJwkDocument>();
}

#[test]
fn binary_optional_bytes_distinguish_absence_from_present_empty() -> Result<(), DecodeError> {
    let absent = CryptoHkdfExtractSha384Request::decode_from_slice(&[])?;
    let present = CryptoHkdfExtractSha384Request::decode_from_slice(&[0x12, 0])?;
    assert!(absent.salt.is_none());
    assert_eq!(present.salt.as_deref(), Some([].as_slice()));
    assert!(absent.encode_to_vec().is_empty());
    assert_eq!(present.encode_to_vec(), [0x12, 0]);

    let mut present = present;
    present.merge_from_slice(&[0x12, 1, 7])?;
    assert_eq!(present.salt.as_deref(), Some([7].as_slice()));
    present.merge_from_slice(&[0x12, 0])?;
    assert_eq!(present.salt.as_deref(), Some([].as_slice()));
    Message::clear(&mut present);
    assert!(present.salt.is_none());
    Ok(())
}

#[test]
fn optional_json_preserves_null_empty_and_nonempty_values() -> Result<(), serde_json::Error> {
    for (json, expected) in [
        (r#"{}"#, None),
        (r#"{"salt":null}"#, None),
        (r#"{"salt":""}"#, Some(Vec::new())),
        (r#"{"salt":"AA=="}"#, Some(vec![0])),
    ] {
        let request: CryptoHkdfExtractSha384Request = serde_json::from_str(json)?;
        assert_eq!(request.salt.as_deref(), expected.as_deref());
        let encoded = serde_json::to_value(&request)?;
        assert_eq!(encoded.get("salt").is_some(), expected.is_some());
    }
    let options: CryptoJwkOptions = serde_json::from_str(r#"{"kid":""}"#)?;
    assert_eq!(options.kid.as_deref(), Some([].as_slice()));
    assert_eq!(
        serde_json::to_value(&options)?.get("kid"),
        Some(&serde_json::json!(""))
    );
    Ok(())
}

#[test]
fn optional_scalar_zero_has_presence_and_closed_json_fields() -> Result<(), DecodeError> {
    let absent = CryptoRsaPssParams::decode_from_slice(&[])?;
    let present = CryptoRsaPssParams::decode_from_slice(&[0x18, 0])?;
    assert_eq!(absent.salt_length, None);
    assert_eq!(present.salt_length, Some(0));
    assert_eq!(present.encode_to_vec(), [0x18, 0]);
    assert!(
        serde_json::from_str::<CryptoRsaPssParams>(r#"{"saltLength":0,"override":1}"#).is_err()
    );
    Ok(())
}

#[test]
#[allow(unsafe_code, clippy::expect_used)]
fn shorter_optional_replacements_wipe_the_initialized_tail() -> Result<(), DecodeError> {
    let mut request = CryptoHkdfExtractSha384Request::default();
    request.salt = Some(vec![0xa5; 64]);
    let allocation = request.salt.as_ref().expect("present salt").as_ptr();
    request.merge_from_slice(&[0x12, 1, 9])?;
    let salt = request.salt.as_ref().expect("presence survives merge");
    assert_eq!(salt, &[9]);
    assert_eq!(salt.as_ptr(), allocation);
    // SAFETY: The same live allocation retains all 64 previously initialized
    // bytes. No reads occur after drop, reallocation, or concurrent mutation.
    let initialized = unsafe { core::slice::from_raw_parts(salt.as_ptr(), 64) };
    assert!(initialized[1..].iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
#[allow(unsafe_code, clippy::expect_used)]
fn malformed_optional_replacements_clear_the_retained_live_buffer() {
    let mut request = CryptoHkdfExtractSha384Request::default();
    request.salt = Some(vec![0xa5; 64]);
    let allocation = request.salt.as_ref().expect("present salt").as_ptr();
    assert!(request.merge_from_slice(&[0x12, 2, 9]).is_err());
    let salt = request
        .salt
        .as_ref()
        .expect("failed merge retains structural presence");
    assert!(salt.is_empty());
    assert_eq!(salt.as_ptr(), allocation);
    // SAFETY: Failed guarded merge retains the same live allocation; all
    // observed bytes were initialized before merge and no mutation is active.
    let initialized = unsafe { core::slice::from_raw_parts(salt.as_ptr(), 64) };
    assert!(initialized.iter().all(|byte| *byte == 0));
}

#[test]
fn generated_optional_setters_preserve_present_empty() {
    let request = CryptoHkdfExtractSha384Request::default()
        .with_salt(vec![0xa5; 64])
        .with_salt(Vec::new());
    assert_eq!(request.salt.as_deref(), Some([].as_slice()));
    let options = CryptoJwkOptions::default()
        .with_kid(b"correlator".to_vec())
        .with_kid(Vec::new());
    assert_eq!(options.kid.as_deref(), Some([].as_slice()));
}

#[test]
fn json_errors_after_owned_optional_values_reject_without_partial_results() {
    for json in [
        r#"{"salt":"cHJpdmF0ZQ==","unknown":true}"#,
        r#"{"salt":"cHJpdmF0ZQ==","salt":""}"#,
        r#"{"salt":"cHJpdmF0ZQ==","inputKeyMaterial":"%%%"}"#,
        r#"{"salt":"cHJpdmF0ZQ==","inputKeyMaterial":123}"#,
    ] {
        assert!(serde_json::from_str::<CryptoHkdfExtractSha384Request>(json).is_err());
    }
    assert!(
        serde_json::from_str::<CryptoJwkOptions>(r#"{"kid":"cHJpdmF0ZQ==","alg":[]}"#).is_err()
    );
    assert!(serde_json::from_str::<PublicJwkDocument>(
        r#"{"typed":{"okp":{"kid":"cHJpdmF0ZQ=="}},"unknown":0}"#
    )
    .is_err());
    assert!(
        serde_json::from_str::<PublicJwk>(r#"{"okp":{"kid":"cHJpdmF0ZQ=="},"ec":{}}"#).is_err()
    );
    assert!(serde_json::from_str::<PublicJwks>(
        r#"{"keys":[{"okp":{"kid":"cHJpdmF0ZQ=="}},{"unknown":0}]}"#
    )
    .is_err());
}

#[test]
fn malformed_unknown_groups_keep_original_typed_errors() {
    let missing_end = [0xa3, 0x06, 0x0a, 3, b'k', b'e', b'y'];
    let wrong_end = [0xa3, 0x06, 0x0a, 3, b'k', b'e', b'y', 0xac, 0x06];
    let wrong_nested_end = [
        0xa3, 0x06, 0xab, 0x06, 0x0a, 3, b'k', b'e', b'y', 0xa4, 0x06,
    ];
    assert!(matches!(
        PublicJwkDocument::decode_from_slice(&missing_end),
        Err(DecodeError::UnexpectedEof)
    ));
    assert!(matches!(
        PublicJwkDocument::decode_from_slice(&wrong_end),
        Err(DecodeError::InvalidEndGroup(101))
    ));
    assert!(matches!(
        PublicJwkDocument::decode_from_slice(&wrong_nested_end),
        Err(DecodeError::InvalidEndGroup(100))
    ));
}

#[test]
fn unknown_group_wire_and_budgets_remain_unchanged() -> Result<(), DecodeError> {
    let encoded = [0xa3, 0x06, 0x0a, 3, b'k', b'e', b'y', 0xa4, 0x06];
    let document: PublicJwkDocument = DecodeOptions::new()
        .with_unknown_field_limit(2)
        .decode_from_slice(&encoded)?;
    assert_eq!(document.unknown_fields().len(), 1);
    assert_eq!(document.encode_to_vec(), encoded);
    let limited: Result<PublicJwkDocument, _> = DecodeOptions::new()
        .with_unknown_field_limit(1)
        .decode_from_slice(&encoded);
    assert!(matches!(
        limited,
        Err(DecodeError::UnknownFieldLimitExceeded)
    ));
    let no_depth: Result<PublicJwkDocument, _> = DecodeOptions::new()
        .with_recursion_limit(0)
        .decode_from_slice(&encoded);
    assert!(matches!(no_depth, Err(DecodeError::RecursionLimitExceeded)));
    assert!(reallyme_crypto_proto::wire::decode_protobuf::<PublicJwkDocument>(&encoded).is_err());
    Ok(())
}

#[test]
fn custom_option_owners_keep_protojson_null_boolean_defaults() -> Result<(), serde_json::Error> {
    let options: CryptoJwkOptions =
        serde_json::from_str(r#"{"alg":null,"useSig":null,"useEnc":null,"kid":""}"#)?;
    assert!(!options.alg);
    assert!(!options.use_sig);
    assert!(!options.use_enc);
    assert_eq!(options.kid.as_deref(), Some([].as_slice()));
    let options: CryptoJwkOptions =
        serde_json::from_str(r#"{"alg":true,"useSig":false,"useEnc":true,"kid":null}"#)?;
    assert!(options.alg);
    assert!(!options.use_sig);
    assert!(options.use_enc);
    assert!(options.kid.is_none());
    Ok(())
}
