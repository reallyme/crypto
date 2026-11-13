// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed prime-group imports and standalone protected native operations.
//! No private scalar export or caller-defined domain parameters are accepted.

use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoNativeAgreementResult, CryptoNativeKeyCapabilities, CryptoNativePublicKeyRequest,
    CryptoPrimeGroupCurveCoefficients, CryptoPrimeGroupDhParametersValidationRequest,
    CryptoPrimeGroupDhParametersValidationResult, CryptoPrimeGroupDomainRequest,
    CryptoPrimeGroupDomainResult, CryptoPrimeGroupElement, CryptoPrimeGroupFieldValue,
    CryptoPrimeGroupIdentifier, CryptoPrimeGroupLinearCombinationRequest,
    CryptoPrimeGroupMultiplyRequest, CryptoPrimeGroupReduceToFieldRequest,
    CryptoPrimeGroupScalarDescriptor, CryptoPrimeGroupScalarGenerateRequest,
    CryptoPrimeGroupScalarImportRequest, NativeKeySource, PrimeGroup as ProtoGroup,
};
use secrecy::{ExposeSecret, SecretSlice};

use super::{GroupElement, GroupScalar, PrimeGroup};
use crate::native_contract_support::{capabilities, copy_bytes, known_fields};

fn group(value: Option<&CryptoPrimeGroupIdentifier>) -> Result<PrimeGroup, CryptoError> {
    PrimeGroup::try_from(value.ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?)
}
fn identifier(value: PrimeGroup) -> CryptoPrimeGroupIdentifier {
    CryptoPrimeGroupIdentifier {
        group: ProtoGroup::from(value).into(),
        __buffa_unknown_fields: Default::default(),
    }
}
/// Validate explicit canonical DH parameters using the selected built-in domain.
/// Optional bytes are borrowed exactly; presence never implies acceptance.
pub fn validate_dh_parameters(
    request: &CryptoPrimeGroupDhParametersValidationRequest,
) -> Result<CryptoPrimeGroupDhParametersValidationResult, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    let group = group(request.group.as_option())?;
    group.validate_dh_parameters(
        &request.p,
        &request.g,
        request.q.as_deref(),
        request.j.as_deref(),
    )?;
    Ok(CryptoPrimeGroupDhParametersValidationResult {
        group: MessageField::some(identifier(group)),
        __buffa_unknown_fields: Default::default(),
    })
}
impl TryFrom<&CryptoPrimeGroupScalarImportRequest> for GroupScalar {
    type Error = CryptoError;
    fn try_from(request: &CryptoPrimeGroupScalarImportRequest) -> Result<Self, Self::Error> {
        known_fields(request.__buffa_unknown_fields.is_empty())?;
        group(request.group.as_option())?.scalar(&request.scalar)
    }
}
impl TryFrom<&CryptoPrimeGroupElement> for GroupElement {
    type Error = CryptoError;
    fn try_from(value: &CryptoPrimeGroupElement) -> Result<Self, Self::Error> {
        known_fields(value.__buffa_unknown_fields.is_empty())?;
        group(value.group.as_option())?.element(&value.encoding)
    }
}
impl TryFrom<&GroupElement> for CryptoPrimeGroupElement {
    type Error = CryptoError;
    fn try_from(value: &GroupElement) -> Result<Self, Self::Error> {
        let mut output = Self {
            group: MessageField::some(identifier(value.group())),
            encoding: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        };
        copy_bytes(&mut output.encoding, value.encoding())?;
        Ok(output)
    }
}
/// Generate a scalar in its existing secrecy owner using OS entropy.
pub fn generate_scalar(
    request: &CryptoPrimeGroupScalarGenerateRequest,
) -> Result<GroupScalar, CryptoError> {
    generate_scalar_with_rng(request, &mut crate::key_random::SystemKeyRng)
}
/// Generate with the existing injected cryptographic entropy boundary.
pub fn generate_scalar_with_rng(
    request: &CryptoPrimeGroupScalarGenerateRequest,
    rng: &mut impl crate::key_random::KeyRng,
) -> Result<GroupScalar, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    group(request.group.as_option())?.random_scalar(rng)
}
/// The descriptor exposes only the standard-generator public element.
pub fn describe_scalar(
    scalar: &GroupScalar,
) -> Result<CryptoPrimeGroupScalarDescriptor, CryptoError> {
    let public = scalar.public_element()?;
    Ok(CryptoPrimeGroupScalarDescriptor {
        public_element: MessageField::some(CryptoPrimeGroupElement::try_from(&public)?),
        capabilities: MessageField::some(scalar_capabilities()?),
        __buffa_unknown_fields: Default::default(),
    })
}
fn scalar_capabilities() -> Result<CryptoNativeKeyCapabilities, CryptoError> {
    // GroupScalar has drop cleanup but does not publish explicit Zeroize or a
    // raw-scalar borrow. The descriptor must not invent those capabilities.
    capabilities(
        NativeKeySource::NATIVE_KEY_SOURCE_SOFTWARE_OWNER,
        false,
        true,
        false,
        false,
    )
}
/// Supplied-base multiplication preserves native domain/subgroup checks.
pub fn multiply(
    scalar: &GroupScalar,
    request: &CryptoPrimeGroupMultiplyRequest,
) -> Result<GroupElement, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    let base = GroupElement::try_from(
        request
            .base
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    scalar.multiply(&base)
}
/// Compute the existing bounded linear combination without changing n's bytes.
pub fn linear_combination(
    request: &CryptoPrimeGroupLinearCombinationRequest,
) -> Result<GroupElement, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    let base = GroupElement::try_from(
        request
            .base
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    let offset = GroupElement::try_from(
        request
            .offset
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    group(request.group.as_option())?.linear_combination(&request.coefficient, &base, &offset)
}
/// Protected reduction output bound to its actual standard field.
pub struct ReducedField {
    group: PrimeGroup,
    value: SecretSlice<u8>,
}
impl zeroize::ZeroizeOnDrop for ReducedField {}
impl ReducedField {
    /// The field identity selected for this reduction.
    #[must_use]
    pub const fn group(&self) -> PrimeGroup {
        self.group
    }
    /// Borrow the clearing result without creating another owner.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.value.expose_secret()
    }
}
/// Preserve constant-time bounded reduction and its native secrecy owner.
pub fn reduce_to_field(
    request: &CryptoPrimeGroupReduceToFieldRequest,
) -> Result<ReducedField, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    let group = group(request.group.as_option())?;
    Ok(ReducedField {
        group,
        value: group.reduce_to_field(&request.input)?,
    })
}
/// Copy through a clearing DTO while retaining the actual reduction domain.
pub fn field_result(value: &ReducedField) -> Result<CryptoPrimeGroupFieldValue, CryptoError> {
    let mut output = CryptoPrimeGroupFieldValue {
        group: MessageField::some(identifier(value.group)),
        value: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    copy_bytes(&mut output.value, value.as_bytes())?;
    Ok(output)
}
/// Existing field encoding owns all canonical/nonzero/domain validation.
pub fn encode_field(request: &CryptoPrimeGroupFieldValue) -> Result<GroupElement, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    group(request.group.as_option())?.encode_field(&request.value)
}
/// Return the existing clearing x-coordinate/DH-value agreement owner.
pub fn agreement_secret(element: &GroupElement) -> Result<SecretSlice<u8>, CryptoError> {
    element.agreement_secret()
}
/// Explicit protected transport copy; native owners remain caller-held.
pub fn agreement_result(
    secret: &SecretSlice<u8>,
) -> Result<CryptoNativeAgreementResult, CryptoError> {
    let mut output = CryptoNativeAgreementResult::default();
    copy_bytes(&mut output.shared_secret, secret.expose_secret())?;
    Ok(output)
}
/// Read only standard domain metadata; no user parameters select arithmetic.
pub fn domain(
    request: &CryptoPrimeGroupDomainRequest,
) -> Result<CryptoPrimeGroupDomainResult, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    let group = group(request.group.as_option())?;
    let mut output = CryptoPrimeGroupDomainResult {
        group: MessageField::some(identifier(group)),
        field_length: u32::try_from(group.field_len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?,
        scalar_length: u32::try_from(group.scalar_len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?,
        element_length: u32::try_from(group.element_len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?,
        modulus: Vec::new(),
        subgroup_order: Vec::new(),
        standard_generator: Vec::new(),
        curve_coefficients: MessageField::none(),
        __buffa_unknown_fields: Default::default(),
    };
    copy_bytes(&mut output.modulus, group.modulus())?;
    copy_bytes(&mut output.subgroup_order, group.order())?;
    copy_bytes(
        &mut output.standard_generator,
        group.standard_generator_encoding(),
    )?;
    if let Some((a, b)) = group.curve_coefficients() {
        let mut coefficients = CryptoPrimeGroupCurveCoefficients::default();
        copy_bytes(&mut coefficients.a, a)?;
        copy_bytes(&mut coefficients.b, b)?;
        output.curve_coefficients = MessageField::some(coefficients);
    }
    Ok(output)
}

/// Return the existing validated standard generator as a clearing element.
pub fn generator(request: &CryptoPrimeGroupDomainRequest) -> Result<GroupElement, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    group(request.group.as_option())?.generator()
}
/// Borrow a private scalar only to compute its standard-generator public key.
pub fn public_element(
    scalar: &GroupScalar,
    request: &CryptoNativePublicKeyRequest,
) -> Result<GroupElement, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    scalar.public_element()
}
/// Import/validate an explicit element before extracting its native agreement bytes.
pub fn agreement_secret_from_proto(
    element: &CryptoPrimeGroupElement,
) -> Result<SecretSlice<u8>, CryptoError> {
    GroupElement::try_from(element)?.agreement_secret()
}
