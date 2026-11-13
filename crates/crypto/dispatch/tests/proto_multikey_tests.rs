// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone dispatch contracts preserve native encoding, policy and ownership.

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// Install clearing generated owners before assigning fields, including fixtures.
#![allow(clippy::field_reassign_with_default)]

use buffa::{EnumValue, Enumeration, Message, MessageField};
use crypto_core::Algorithm;
use crypto_dispatch::proto_multikey::{
    GenerateMultikeyKeypairInputs, ProtectedGeneratedMultikeyKeypair, PublicKeyToMultikeyInputs,
    VerificationMethodMultikeyInputs,
};
use crypto_dispatch::AlgorithmError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoGenerateMultikeyKeypairRequest, CryptoGenerateMultikeyKeypairResult,
    CryptoKeyAlgorithmIdentifier, CryptoPublicKeyToMultikeyRequest,
    CryptoPublicKeyToMultikeyResult, CryptoVerificationMethodMultikeyRequest,
    CryptoVerificationMethodMultikeyResult, KeyAlgorithm,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn identity(algorithm: Algorithm) -> CryptoKeyAlgorithmIdentifier {
    CryptoKeyAlgorithmIdentifier {
        algorithm: KeyAlgorithm::from(algorithm).into(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn generation(algorithm: Algorithm) -> CryptoGenerateMultikeyKeypairRequest {
    let mut output = CryptoGenerateMultikeyKeypairRequest::default();
    output.algorithm = MessageField::some(identity(algorithm));
    output
}

fn binding(
    algorithm: Algorithm,
    kind: &[u8],
    key: &[u8],
) -> CryptoVerificationMethodMultikeyRequest {
    let mut output = CryptoVerificationMethodMultikeyRequest::default();
    output.algorithm = MessageField::some(identity(algorithm));
    output.binding_type.extend_from_slice(kind);
    output.public_key_multibase.extend_from_slice(key);
    output
}

#[test]
fn every_generated_identity_uses_the_existing_total_core_bridge() {
    for value in KeyAlgorithm::values() {
        let mut request = CryptoGenerateMultikeyKeypairRequest::default();
        let mut identifier = CryptoKeyAlgorithmIdentifier::default();
        identifier.algorithm = (*value).into();
        let expected = Algorithm::try_from(&identifier);
        request.algorithm = MessageField::some(identifier);
        match expected {
            Ok(native) => assert_eq!(
                GenerateMultikeyKeypairInputs::try_from(&request)
                    .expect("known native identity")
                    .algorithm(),
                native
            ),
            Err(error) => assert_eq!(
                GenerateMultikeyKeypairInputs::try_from(&request).err(),
                Some(error)
            ),
        }
    }
    for unknown in [i32::MIN, -1, 1, 99, 999_999, i32::MAX] {
        let mut request = generation(Algorithm::Ed25519);
        let mut identifier = CryptoKeyAlgorithmIdentifier::default();
        identifier.algorithm = EnumValue::from(unknown);
        request.algorithm = MessageField::some(identifier);
        assert_eq!(
            GenerateMultikeyKeypairInputs::try_from(&request).err(),
            Some(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
}

#[test]
fn missing_identity_and_unknown_modifiers_fail_closed() {
    let mut request = CryptoGenerateMultikeyKeypairRequest::default();
    assert_eq!(
        GenerateMultikeyKeypairInputs::try_from(&request).err(),
        Some(AlgorithmError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut identifier = identity(Algorithm::Ed25519);
    identifier
        .merge_from_slice(&[0xa0, 0x06, 0x01])
        .expect("unknown nested field");
    request.algorithm = MessageField::some(identifier);
    assert_eq!(
        GenerateMultikeyKeypairInputs::try_from(&request).err(),
        Some(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    request = generation(Algorithm::Ed25519);
    request
        .merge_from_slice(&[0xa0, 0x06, 0x01])
        .expect("unknown top-level field");
    assert_eq!(
        GenerateMultikeyKeypairInputs::try_from(&request).err(),
        Some(AlgorithmError::PRIMITIVE_INVALID_PARAMETER)
    );

    let mut public = CryptoPublicKeyToMultikeyRequest::default();
    assert_eq!(
        PublicKeyToMultikeyInputs::try_from(&public).err(),
        Some(AlgorithmError::PRIMITIVE_INVALID_PARAMETER)
    );
    public.algorithm = MessageField::some(identity(Algorithm::Ed25519));
    public
        .merge_from_slice(&[0xa0, 0x06, 0x01])
        .expect("unknown public-key modifier");
    assert_eq!(
        PublicKeyToMultikeyInputs::try_from(&public).err(),
        Some(AlgorithmError::PRIMITIVE_INVALID_PARAMETER)
    );

    let mut request = binding(Algorithm::SlhDsaSha2_128s, b"Multikey", b"invalid");
    request
        .merge_from_slice(&[0xa0, 0x06, 0x01])
        .expect("unknown binding modifier");
    assert_eq!(
        VerificationMethodMultikeyInputs::try_from(&request).err(),
        Some(AlgorithmError::PRIMITIVE_INVALID_PARAMETER)
    );
}

#[test]
fn all_new_byte_and_transitive_outputs_have_clearing_owners() {
    fn requires_owner<T: ZeroizeOnDrop>() {}
    requires_owner::<CryptoGenerateMultikeyKeypairRequest>();
    requires_owner::<CryptoGenerateMultikeyKeypairResult>();
    requires_owner::<CryptoPublicKeyToMultikeyRequest>();
    requires_owner::<CryptoPublicKeyToMultikeyResult>();
    requires_owner::<CryptoVerificationMethodMultikeyRequest>();
    requires_owner::<CryptoVerificationMethodMultikeyResult>();
    requires_owner::<ProtectedGeneratedMultikeyKeypair>();
    requires_owner::<PublicKeyToMultikeyInputs>();
    requires_owner::<VerificationMethodMultikeyInputs>();
}

#[test]
fn protected_inputs_preserve_exact_bytes_and_explicit_cleanup() {
    let mut request = CryptoPublicKeyToMultikeyRequest::default();
    request.algorithm = MessageField::some(identity(Algorithm::SlhDsaSha2_128s));
    request.public_key.extend_from_slice(&[0, 0xff, 0x80, 0]);
    let mut inputs = PublicKeyToMultikeyInputs::try_from(&request).expect("protected copy");
    assert_eq!(inputs.public_key(), request.public_key);
    inputs.zeroize();
    assert!(inputs.public_key().is_empty());
    // The existing caller-owned request is a separate clearing owner.
    assert_eq!(request.public_key, [0, 0xff, 0x80, 0]);

    let request = binding(
        Algorithm::SlhDsaSha2_128s,
        " Multikey\0é ".as_bytes(),
        "z\0é\u{fdd0}".as_bytes(),
    );
    let mut inputs = VerificationMethodMultikeyInputs::try_from(&request).expect("exact UTF-8");
    assert_eq!(inputs.binding_type().as_bytes(), request.binding_type);
    assert_eq!(
        inputs.public_key_multibase().as_bytes(),
        request.public_key_multibase
    );
    assert_eq!(
        inputs.validate().err(),
        Some(AlgorithmError::PRIMITIVE_INVALID_KEY)
    );
    inputs.zeroize();
    assert!(inputs.binding_type().is_empty());
    assert!(inputs.public_key_multibase().is_empty());
}

#[test]
fn legacy_slh_binding_policy_and_utf8_errors_are_preserved() {
    // Existing structural binding permits the SLH identity before parsing even
    // though software multikey generation/encoding does not implement it.
    let request = binding(Algorithm::SlhDsaSha2_128s, b"Multikey", b"invalid");
    assert_eq!(
        VerificationMethodMultikeyInputs::try_from(&request)
            .expect("native policy permits structural parsing")
            .validate()
            .err(),
        Some(AlgorithmError::PRIMITIVE_INVALID_KEY)
    );
    for request in [
        binding(Algorithm::SlhDsaSha2_128s, &[0xff], b"invalid"),
        binding(Algorithm::SlhDsaSha2_128s, b"Multikey", &[0xff]),
    ] {
        assert_eq!(
            VerificationMethodMultikeyInputs::try_from(&request).err(),
            Some(AlgorithmError::PRIMITIVE_INVALID_ENCODING)
        );
    }
    assert_eq!(
        GenerateMultikeyKeypairInputs::try_from(&generation(Algorithm::SlhDsaSha2_128s))
            .expect("known identity")
            .generate()
            .err(),
        Some(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let mut request = CryptoPublicKeyToMultikeyRequest::default();
    request.algorithm = MessageField::some(identity(Algorithm::SlhDsaSha2_128s));
    assert_eq!(
        PublicKeyToMultikeyInputs::try_from(&request)
            .expect("known identity")
            .encode()
            .err(),
        Some(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}

#[cfg(not(feature = "ed25519"))]
#[test]
fn disabled_algorithm_is_rejected_before_untrusted_binding_text() {
    let request = binding(Algorithm::Ed25519, &[0xff], &[0xff]);
    assert_eq!(
        VerificationMethodMultikeyInputs::try_from(&request).err(),
        Some(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    assert_eq!(
        GenerateMultikeyKeypairInputs::try_from(&generation(Algorithm::Ed25519))
            .expect("identity does not enable execution")
            .generate()
            .err(),
        Some(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}

#[cfg(feature = "ed25519")]
#[test]
fn public_encoding_and_structural_binding_match_existing_native_operations() {
    let public = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        .expect("RFC 8032 public key");
    let expected = crypto_dispatch::public_key_to_multikey(Algorithm::Ed25519, &public)
        .expect("native public encoder");
    let mut request = CryptoPublicKeyToMultikeyRequest::default();
    request.algorithm = MessageField::some(identity(Algorithm::Ed25519));
    request.public_key.extend_from_slice(&public);
    let result = PublicKeyToMultikeyInputs::try_from(&request)
        .expect("protected public input")
        .encode()
        .expect("existing native encoding");
    assert_eq!(result.multikey, expected.as_bytes());
    for kind in [
        b"Multikey".as_slice(),
        b"Ed25519VerificationKey2020".as_slice(),
    ] {
        let native = crypto_dispatch::validate_verification_method_multikey(
            Algorithm::Ed25519,
            core::str::from_utf8(kind).expect("fixed public label"),
            &expected,
        );
        let request = binding(Algorithm::Ed25519, kind, expected.as_bytes());
        let adapted = VerificationMethodMultikeyInputs::try_from(&request)
            .expect("known text")
            .validate()
            .map(|_| ());
        assert_eq!(adapted, native);
    }
    let request = binding(Algorithm::Ed25519, b"wrong binding", expected.as_bytes());
    assert_eq!(
        VerificationMethodMultikeyInputs::try_from(&request)
            .expect("known text")
            .validate()
            .err(),
        Some(AlgorithmError::PRIMITIVE_INVALID_KEY)
    );
    request_identity_rejects_empty_public_key();
}

#[cfg(feature = "ed25519")]
fn request_identity_rejects_empty_public_key() {
    let mut request = CryptoPublicKeyToMultikeyRequest::default();
    request.algorithm = MessageField::some(identity(Algorithm::Ed25519));
    assert_eq!(
        PublicKeyToMultikeyInputs::try_from(&request)
            .expect("identity conversion does not preempt native validation")
            .encode()
            .err(),
        Some(AlgorithmError::PRIMITIVE_INVALID_KEY)
    );
}

#[cfg(all(feature = "native", feature = "ed25519"))]
#[test]
fn generated_software_keypair_output_preserves_owners_and_native_binding() {
    let mut owner = GenerateMultikeyKeypairInputs::try_from(&generation(Algorithm::Ed25519))
        .expect("known identity")
        .generate()
        .expect("native software key generation");
    let result = owner.to_result().expect("protected output copy");
    let native = owner.as_native();
    assert_eq!(result.public_key, native.public_key);
    assert_eq!(result.secret_key, native.secret_key.as_slice());
    assert_eq!(
        result.public_key_multikey,
        native.public_key_multikey.as_bytes()
    );
    assert_eq!(
        Algorithm::try_from(result.algorithm.as_option().expect("output identity")),
        Ok(Algorithm::Ed25519)
    );
    assert_eq!(
        crypto_dispatch::public_key_to_multikey(Algorithm::Ed25519, &native.public_key),
        Ok(native.public_key_multikey.clone())
    );
    assert_eq!(
        crypto_dispatch::validate_verification_method_multikey(
            Algorithm::Ed25519,
            "Multikey",
            &native.public_key_multikey,
        ),
        Ok(())
    );
    owner.zeroize();
    assert!(owner.as_native().public_key.is_empty());
    assert!(owner.as_native().secret_key.is_empty());
    assert!(owner.as_native().public_key_multikey.is_empty());
    assert_eq!(
        owner.to_result().err(),
        Some(AlgorithmError::BACKEND_INVALID_STATE)
    );
    // Wiping one owner must not erase another still-live protected result.
    assert!(!result.secret_key.is_empty());
}
