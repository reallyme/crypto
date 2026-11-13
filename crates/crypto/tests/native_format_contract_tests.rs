// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![allow(clippy::field_reassign_with_default)] // Populate already-clearing transport owners.
#![cfg(feature = "operation-response")]

use buffa::{EnumValue, Enumeration, Message, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoKeyAlgorithmIdentifier, CryptoPublicKeyFormatRequest, CryptoPublicKeyFormatResult,
    KeyAlgorithm, PublicKeyFormatOperation,
};
use reallyme_crypto::format_contract::transform_public_key;
use zeroize::ZeroizeOnDrop;

fn request(
    algorithm: KeyAlgorithm,
    operation: PublicKeyFormatOperation,
    bytes: &[u8],
) -> CryptoPublicKeyFormatRequest {
    let mut result = CryptoPublicKeyFormatRequest::default();
    result.algorithm = MessageField::some(CryptoKeyAlgorithmIdentifier {
        algorithm: algorithm.into(),
        __buffa_unknown_fields: Default::default(),
    });
    result.operation = operation.into();
    result.public_key.extend_from_slice(bytes);
    result
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn selectors_presence_unknown_modifiers_and_wire_are_explicit() {
    assert!(
        matches!(transform_public_key(&CryptoPublicKeyFormatRequest::default()), Err(e) if e == CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    for value in PublicKeyFormatOperation::values() {
        // An unspecified key identity must never become an arbitrary copy,
        // including when the format operation itself is registered.
        let probe = request(KeyAlgorithm::KEY_ALGORITHM_UNSPECIFIED, *value, &[]);
        assert!(
            matches!(transform_public_key(&probe), Err(e) if e == CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    for unknown in [i32::MIN, -1, 1, 99, 999, i32::MAX] {
        let mut probe = request(
            KeyAlgorithm::KEY_ALGORITHM_P256,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS,
            &[],
        );
        probe.operation = EnumValue::from(unknown);
        assert!(
            matches!(transform_public_key(&probe), Err(e) if e == CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
        probe.algorithm = MessageField::some(CryptoKeyAlgorithmIdentifier {
            algorithm: EnumValue::from(unknown),
            __buffa_unknown_fields: Default::default(),
        });
        assert!(
            matches!(transform_public_key(&probe), Err(e) if e == CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let wire = [0x0a, 3, 8, 0xc8, 1, 0x10, 0xc8, 1, 0x1a, 4, 0, 255, 32, 0];
    let probe = request(
        KeyAlgorithm::KEY_ALGORITHM_P256,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS,
        &[0, 255, 32, 0],
    );
    assert_eq!(probe.encode_to_vec(), wire);
    let mut modified = probe.encode_to_vec();
    modified.extend_from_slice(&[0xf8, 7, 1]);
    let probe = CryptoPublicKeyFormatRequest::decode_from_slice(&modified).unwrap();
    assert!(
        matches!(transform_public_key(&probe), Err(e) if e == CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let nested_unknown =
        CryptoKeyAlgorithmIdentifier::decode_from_slice(&[8, 0xc8, 1, 0xf8, 7, 1]).unwrap();
    let mut probe = request(
        KeyAlgorithm::KEY_ALGORITHM_P256,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS,
        &[],
    );
    probe.algorithm = MessageField::some(nested_unknown);
    assert!(
        matches!(transform_public_key(&probe), Err(e) if e == CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn protected_format_owners_clear_without_reading_released_memory() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<CryptoPublicKeyFormatRequest>();
    clearing::<CryptoPublicKeyFormatResult>();
    let mut value = request(
        KeyAlgorithm::KEY_ALGORITHM_ED25519,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
        &[1; 32],
    );
    buffa::Message::clear(&mut value);
    assert!(value.public_key.is_empty() || value.public_key.iter().all(|byte| *byte == 0));
}

#[cfg(all(feature = "p256", any(feature = "native", feature = "wasm")))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn nist_sec1_transforms_match_existing_leaf_and_fail_on_wrong_points() -> Result<(), CryptoError> {
    use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_public_key_format_result::Representation;
    let public = hex::decode("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap();
    let compressed = transform_public_key(&request(
        KeyAlgorithm::KEY_ALGORITHM_P256,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS,
        &public,
    ))?;
    let Some(Representation::Encoded(compressed)) = compressed.representation.as_ref() else {
        return Err(CryptoError::BACKEND_INTERNAL);
    };
    assert_eq!(compressed.value, crypto_p256::compress_p256(&public)?);
    let uncompressed = transform_public_key(&request(
        KeyAlgorithm::KEY_ALGORITHM_P256,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS,
        &compressed.value,
    ))?;
    let Some(Representation::Encoded(uncompressed)) = uncompressed.representation.as_ref() else {
        return Err(CryptoError::BACKEND_INTERNAL);
    };
    assert_eq!(uncompressed.value, public);
    for bytes in [&[][..], &[0; 33][..], &[4; 65][..]] {
        let probe = request(
            KeyAlgorithm::KEY_ALGORITHM_P256,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS,
            bytes,
        );
        assert!(
            matches!(transform_public_key(&probe), Err(error) if error == CryptoError::PRIMITIVE_INVALID_KEY)
        );
    }
    Ok(())
}

#[cfg(all(feature = "secp256k1", any(feature = "native", feature = "wasm")))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn secp256k1_shape_check_and_curve_validation_remain_distinct() -> Result<(), CryptoError> {
    let mut non_point = [255; 33];
    non_point[0] = 2;
    for operation in [
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT,
    ] {
        transform_public_key(&request(
            KeyAlgorithm::KEY_ALGORITHM_SECP256K1,
            operation,
            &non_point,
        ))?;
    }
    assert!(matches!(transform_public_key(&request(
        KeyAlgorithm::KEY_ALGORITHM_SECP256K1,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS,
        &non_point
    )), Err(error) if error == CryptoError::PRIMITIVE_INVALID_KEY));
    let generator =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
    for operation in [
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE,
    ] {
        transform_public_key(&request(
            KeyAlgorithm::KEY_ALGORITHM_SECP256K1,
            operation,
            &generator[1..],
        ))?;
        assert!(matches!(transform_public_key(&request(
            KeyAlgorithm::KEY_ALGORITHM_SECP256K1,
            operation,
            &[]
        )), Err(error) if error == CryptoError::PRIMITIVE_INVALID_KEY));
    }
    let result = transform_public_key(&request(
        KeyAlgorithm::KEY_ALGORITHM_SECP256K1,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS,
        &generator,
    ))?;
    use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_public_key_format_result::Representation;
    let Some(Representation::Affine(value)) = result.representation.as_ref() else {
        return Err(CryptoError::BACKEND_INTERNAL);
    };
    let expected = crypto_secp256k1::decompress_secp256k1_public_key(&generator)?;
    assert_eq!((&value.x, &value.y), (&expected.0, &expected.1));
    Ok(())
}

#[cfg(feature = "ed25519")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn ed25519_deep_identity_validation_is_preserved() -> Result<(), CryptoError> {
    let valid =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    transform_public_key(&request(
        KeyAlgorithm::KEY_ALGORITHM_ED25519,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY,
        &valid,
    ))?;
    for invalid in [&[][..], &[0; 32][..], &[255; 32][..]] {
        let expected = crypto_ed25519::validate_public_key_identity(invalid).unwrap_err();
        assert!(
            matches!(transform_public_key(&request(KeyAlgorithm::KEY_ALGORITHM_ED25519, PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY, invalid)), Err(e) if e == expected)
        );
    }
    Ok(())
}

#[cfg(any(feature = "native", feature = "wasm"))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn fixed_public_key_helpers_preserve_leaf_validation_and_error_parity() -> Result<(), CryptoError> {
    use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_public_key_format_result::Representation;
    // Feature selection must not turn unimplemented format helpers into
    // successful length-only copies. Compare actual leaf behavior for each.
    let check = |algorithm,
                 operation,
                 bytes: &[u8],
                 expected: Result<Vec<u8>, CryptoError>|
     -> Result<(), CryptoError> {
        let actual = transform_public_key(&request(algorithm, operation, bytes));
        match expected {
            Ok(expected) => {
                let output = actual?;
                let Some(Representation::Encoded(value)) = output.representation.as_ref() else {
                    return Err(CryptoError::BACKEND_INTERNAL);
                };
                assert_eq!(value.value, expected);
            }
            Err(expected) => assert!(matches!(actual,Err(error) if error==expected)),
        }
        Ok(())
    };
    // Keep this closure meaningful even in a lane with every leaf disabled.
    check(
        KeyAlgorithm::KEY_ALGORITHM_UNSPECIFIED,
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
        &[],
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    )?;
    #[cfg(feature = "ml-dsa-44")]
    {
        for bytes in [
            vec![0; crypto_ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN],
            Vec::new(),
            vec![0; crypto_ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN + 1],
        ] {
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
                &bytes,
                crypto_ml_dsa_44::encode_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
                &bytes,
                crypto_ml_dsa_44::decode_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT,
                &bytes,
                crypto_ml_dsa_44::assert_public_key(&bytes).map(<[u8]>::to_vec),
            )?;
        }
    }
    #[cfg(feature = "ml-dsa-65")]
    {
        for bytes in [
            vec![0; crypto_ml_dsa_65::ML_DSA_65_PUBLIC_KEY_LEN],
            Vec::new(),
            vec![0; crypto_ml_dsa_65::ML_DSA_65_PUBLIC_KEY_LEN + 1],
        ] {
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
                &bytes,
                crypto_ml_dsa_65::encode_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
                &bytes,
                crypto_ml_dsa_65::decode_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT,
                &bytes,
                crypto_ml_dsa_65::assert_public_key(&bytes).map(<[u8]>::to_vec),
            )?;
        }
    }
    #[cfg(feature = "ml-dsa-87")]
    {
        for bytes in [
            vec![0; crypto_ml_dsa_87::ML_DSA_87_PUBLIC_KEY_LEN],
            Vec::new(),
            vec![0; crypto_ml_dsa_87::ML_DSA_87_PUBLIC_KEY_LEN + 1],
        ] {
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
                &bytes,
                crypto_ml_dsa_87::encode_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
                &bytes,
                crypto_ml_dsa_87::decode_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT,
                &bytes,
                crypto_ml_dsa_87::assert_public_key(&bytes).map(<[u8]>::to_vec),
            )?;
        }
    }
    #[cfg(feature = "ml-kem-512")]
    {
        for bytes in [
            vec![0; crypto_ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN],
            Vec::new(),
            vec![0; crypto_ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN + 1],
        ] {
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
                &bytes,
                crypto_ml_kem_512::encode_ml_kem_512_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
                &bytes,
                crypto_ml_kem_512::decode_ml_kem_512_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT,
                &bytes,
                crypto_ml_kem_512::assert_ml_kem_512_public_key(&bytes).map(<[u8]>::to_vec),
            )?;
        }
    }
    #[cfg(feature = "ml-kem-768")]
    {
        for bytes in [
            vec![0; crypto_ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN],
            Vec::new(),
            vec![0; crypto_ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN + 1],
        ] {
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
                &bytes,
                crypto_ml_kem_768::encode_ml_kem_768_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
                &bytes,
                crypto_ml_kem_768::decode_ml_kem_768_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT,
                &bytes,
                crypto_ml_kem_768::assert_ml_kem_768_public_key(&bytes).map(<[u8]>::to_vec),
            )?;
        }
    }
    #[cfg(feature = "ml-kem-1024")]
    {
        for bytes in [
            vec![0; crypto_ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN],
            Vec::new(),
            vec![0; crypto_ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN + 1],
        ] {
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
                &bytes,
                crypto_ml_kem_1024::encode_ml_kem_1024_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
                &bytes,
                crypto_ml_kem_1024::decode_ml_kem_1024_public_key(&bytes),
            )?;
            check(
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024,
                PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT,
                &bytes,
                crypto_ml_kem_1024::assert_ml_kem_1024_public_key(&bytes).map(<[u8]>::to_vec),
            )?;
        }
    }
    #[cfg(feature = "x-wing")]
    for bytes in [
        vec![0; crypto_x_wing::X_WING_768_PUBLIC_KEY_LEN],
        Vec::new(),
    ] {
        for operation in [
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
        ] {
            check(
                KeyAlgorithm::KEY_ALGORITHM_X_WING_768,
                operation,
                &bytes,
                reallyme_crypto::operations::key_encoding::copy_fixed_public_key(
                    &bytes,
                    crypto_x_wing::X_WING_768_PUBLIC_KEY_LEN,
                ),
            )?;
        }
    }
    #[cfg(feature = "slh-dsa")]
    for bytes in [
        vec![0; crypto_slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN],
        Vec::new(),
    ] {
        check(
            KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
            &bytes,
            crypto_slh_dsa::encode_slh_dsa_sha2_128s_public_key(&bytes),
        )?;
        check(
            KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
            &bytes,
            crypto_slh_dsa::decode_slh_dsa_sha2_128s_public_key(&bytes),
        )?;
    }
    #[cfg(feature = "x25519")]
    for bytes in [vec![9; 32], Vec::new(), vec![0; 32]] {
        check(
            KeyAlgorithm::KEY_ALGORITHM_X25519,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
            &bytes,
            crypto_x25519::encode_public_key(&bytes),
        )?;
        check(
            KeyAlgorithm::KEY_ALGORITHM_X25519,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
            &bytes,
            crypto_x25519::decode_public_key(&bytes),
        )?;
        check(
            KeyAlgorithm::KEY_ALGORITHM_X25519,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT,
            &bytes,
            crypto_x25519::assert_public_key(&bytes).map(<[u8]>::to_vec),
        )?;
    }
    #[cfg(feature = "ed25519")]
    for bytes in [
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap(),
        Vec::new(),
        vec![0; 32],
    ] {
        check(
            KeyAlgorithm::KEY_ALGORITHM_ED25519,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE,
            &bytes,
            crypto_ed25519::encode_public_key(&bytes),
        )?;
        check(
            KeyAlgorithm::KEY_ALGORITHM_ED25519,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE,
            &bytes,
            crypto_ed25519::decode_public_key(&bytes),
        )?;
        check(
            KeyAlgorithm::KEY_ALGORITHM_ED25519,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT,
            &bytes,
            crypto_ed25519::assert_public_key(&bytes).map(<[u8]>::to_vec),
        )?;
    }
    Ok(())
}

#[cfg(all(
    any(feature = "p384", feature = "p521"),
    any(feature = "native", feature = "wasm")
))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn larger_nist_sec1_helpers_match_independent_public_points() -> Result<(), CryptoError> {
    use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_public_key_format_result::Representation;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("data/ecdsa_explicit.json")).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let algorithm = match vector["curve"].as_str().unwrap() {
            #[cfg(feature = "p384")]
            "P384" => KeyAlgorithm::KEY_ALGORITHM_P384,
            #[cfg(feature = "p521")]
            "P521" => KeyAlgorithm::KEY_ALGORITHM_P521,
            _ => continue,
        };
        let public = hex::decode(vector["public"].as_str().unwrap()).unwrap();
        let result = transform_public_key(&request(
            algorithm,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS,
            &public,
        ))?;
        let Some(Representation::Encoded(compressed)) = result.representation.as_ref() else {
            return Err(CryptoError::BACKEND_INTERNAL);
        };
        let result = transform_public_key(&request(
            algorithm,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS,
            &compressed.value,
        ))?;
        let Some(Representation::Encoded(uncompressed)) = result.representation.as_ref() else {
            return Err(CryptoError::BACKEND_INTERNAL);
        };
        assert_eq!(uncompressed.value, public);
        let invalid = vec![0; public.len()];
        assert!(matches!(transform_public_key(&request(
            algorithm,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS,
            &invalid
        )), Err(error) if error == CryptoError::PRIMITIVE_INVALID_KEY));
        assert!(matches!(transform_public_key(&request(
            algorithm,
            PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS,
            &[]
        )), Err(error) if error == CryptoError::PRIMITIVE_INVALID_KEY));
    }
    Ok(())
}

#[cfg(feature = "secp256k1")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn secp256k1_transcoding_retains_scalars_without_requiring_a_backend_lane(
) -> Result<(), CryptoError> {
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        CryptoSecp256k1SignatureTranscodeRequest, EcdsaEncoding,
    };
    let mut raw = [0; 64];
    raw[31] = 1;
    raw[63] = 1;
    let mut request = CryptoSecp256k1SignatureTranscodeRequest::default();
    request.source_encoding = EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH.into();
    request.target_encoding = EcdsaEncoding::ECDSA_ENCODING_DER.into();
    request.signature.extend_from_slice(&raw);
    let der = reallyme_crypto::format_contract::transcode_secp256k1_signature(&request)?;
    assert_eq!(der.signature, [0x30, 6, 2, 1, 1, 2, 1, 1]);
    request.source_encoding = EcdsaEncoding::ECDSA_ENCODING_DER.into();
    request.target_encoding = EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH.into();
    request.signature = der.signature.clone();
    assert_eq!(
        reallyme_crypto::format_contract::transcode_secp256k1_signature(&request)?.signature,
        raw
    );
    request.signature = vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1];
    let expected =
        crypto_secp256k1::secp256k1_ecdsa_der_to_jose_signature(&request.signature).unwrap_err();
    assert!(
        matches!(reallyme_crypto::format_contract::transcode_secp256k1_signature(&request),Err(e)if e==expected)
    );
    Ok(())
}
