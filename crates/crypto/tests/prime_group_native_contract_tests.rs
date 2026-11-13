// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![allow(clippy::field_reassign_with_default)] // Construct clearing owners before populating bytes.
#![cfg(all(feature = "operation-response", feature = "prime-groups"))]

use buffa::{Enumeration, Message, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPrimeGroupDomainRequest, CryptoPrimeGroupElement, CryptoPrimeGroupIdentifier,
    CryptoPrimeGroupLinearCombinationRequest, CryptoPrimeGroupMultiplyRequest,
    CryptoPrimeGroupReduceToFieldRequest, CryptoPrimeGroupScalarImportRequest,
    PrimeGroup as ProtoGroup,
};
use reallyme_crypto::prime_groups::{contract, GroupElement, GroupScalar, PrimeGroup};
use secrecy::ExposeSecret;

fn identifier(group: PrimeGroup) -> CryptoPrimeGroupIdentifier {
    let mut value = CryptoPrimeGroupIdentifier::default();
    value.group = ProtoGroup::from(group).into();
    value
}
fn scalar(group: PrimeGroup) -> CryptoPrimeGroupScalarImportRequest {
    let mut value = CryptoPrimeGroupScalarImportRequest::default();
    value.group = MessageField::some(identifier(group));
    value.scalar.resize(group.scalar_len(), 0);
    *value.scalar.last_mut().unwrap() = 1;
    value
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_domain_and_scalar_adapter_matches_native_standard_generator() -> Result<(), CryptoError> {
    let mut executed = 0;
    for proto in ProtoGroup::values() {
        if proto.to_i32() == 0 {
            continue;
        }
        let mut selected = CryptoPrimeGroupIdentifier::default();
        selected.group = (*proto).into();
        let group = PrimeGroup::try_from(&selected)?;
        let scalar = GroupScalar::try_from(&scalar(group))?;
        let public = scalar.public_element()?;
        assert_eq!(public.encoding(), group.standard_generator_encoding());
        let encoded = CryptoPrimeGroupElement::try_from(&public)?;
        assert_eq!(
            GroupElement::try_from(&encoded)?.encoding(),
            public.encoding()
        );
        let descriptor = contract::describe_scalar(&scalar)?;
        let capabilities = descriptor.capabilities.as_option().unwrap();
        assert!(!capabilities.supports_signing && capabilities.supports_agreement);
        assert!(!capabilities.exposes_private_bytes && !capabilities.supports_explicit_zeroize);
        let mut request = CryptoPrimeGroupDomainRequest::default();
        request.group = MessageField::some(identifier(group));
        let domain = contract::domain(&request)?;
        assert_eq!(domain.modulus, group.modulus());
        assert_eq!(domain.subgroup_order, group.order());
        assert_eq!(
            domain.standard_generator,
            group.standard_generator_encoding()
        );
        assert_eq!(
            domain.curve_coefficients.is_set(),
            group.is_elliptic_curve()
        );
        executed += 1;
    }
    assert_eq!(executed, 10);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn multiplication_reduction_and_linear_combination_preserve_native_values(
) -> Result<(), CryptoError> {
    let group = PrimeGroup::NistP256;
    let scalar = GroupScalar::try_from(&scalar(group))?;
    let generator = group.generator()?;
    let mut multiply = CryptoPrimeGroupMultiplyRequest::default();
    multiply.base = MessageField::some(CryptoPrimeGroupElement::try_from(&generator)?);
    assert_eq!(
        contract::multiply(&scalar, &multiply)?.encoding(),
        generator.encoding()
    );
    let mut combination = CryptoPrimeGroupLinearCombinationRequest::default();
    combination.group = MessageField::some(identifier(group));
    combination.coefficient.push(0);
    combination.base = MessageField::some(CryptoPrimeGroupElement::try_from(&generator)?);
    combination.offset = MessageField::some(CryptoPrimeGroupElement::try_from(&generator)?);
    assert_eq!(
        contract::linear_combination(&combination)?.encoding(),
        generator.encoding()
    );
    let mut request = CryptoPrimeGroupReduceToFieldRequest::default();
    request.group = MessageField::some(identifier(group));
    request.input.extend_from_slice(&[1, 2, 3]);
    let native = group.reduce_to_field(&request.input)?;
    let adapted = contract::reduce_to_field(&request)?;
    assert_eq!(adapted.as_bytes(), native.expose_secret());
    assert_eq!(
        contract::field_result(&adapted)?.value,
        native.expose_secret()
    );
    let agreement = contract::agreement_secret(&generator)?;
    assert_eq!(
        contract::agreement_result(&agreement)?.shared_secret,
        generator.agreement_secret()?.expose_secret()
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wrong_domains_missing_fields_oversized_reduction_and_unknown_modifiers_fail_closed(
) -> Result<(), CryptoError> {
    assert!(
        matches!(GroupScalar::try_from(&CryptoPrimeGroupScalarImportRequest::default()),
        Err(error) if error == CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut source = scalar(PrimeGroup::NistP256);
    source.merge_from_slice(&[0xa0, 0x06, 1]).unwrap();
    assert!(matches!(GroupScalar::try_from(&source),
        Err(error) if error == CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM));
    let scalar = GroupScalar::try_from(&scalar(PrimeGroup::NistP256))?;
    let mut multiply = CryptoPrimeGroupMultiplyRequest::default();
    multiply.base = MessageField::some(CryptoPrimeGroupElement::try_from(
        &PrimeGroup::NistP384.generator()?,
    )?);
    assert!(matches!(contract::multiply(&scalar, &multiply),
        Err(error) if error == CryptoError::PRIMITIVE_INVALID_PARAMETER));
    let mut reduction = CryptoPrimeGroupReduceToFieldRequest::default();
    reduction.group = MessageField::some(identifier(PrimeGroup::NistP256));
    reduction.input.resize(513, 1);
    assert!(matches!(contract::reduce_to_field(&reduction),
        Err(error) if error == CryptoError::PRIMITIVE_INVALID_LENGTH));
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn private_scalars_elements_and_nested_transport_owners_keep_cleanup() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<contract::ReducedField>();
    require_cleanup::<GroupScalar>();
    require_cleanup::<GroupElement>();
    require_cleanup::<CryptoPrimeGroupElement>();
    require_cleanup::<CryptoPrimeGroupScalarImportRequest>();
    require_cleanup::<CryptoPrimeGroupLinearCombinationRequest>();
    require_cleanup::<CryptoPrimeGroupDomainRequest>();
}
