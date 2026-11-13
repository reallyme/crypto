// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Retained independent prime-group known answers and hostile-input coverage.

#![cfg(feature = "prime-groups")]
// Fixed, independently generated public fixtures must decode; failures identify
// a damaged test vector rather than an accepted production error path.
#![allow(clippy::expect_used)]

use crypto_core::CryptoError;
use reallyme_crypto::{
    key_random::KeyRng,
    prime_groups::{GroupScalar, PrimeGroup},
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use zeroize::ZeroizeOnDrop;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    schema_version: u8,
    sources: Vec<String>,
    groups: Vec<Vector>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    group: String,
    domain: Domain,
    answers: Answers,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Domain {
    p: String,
    q: String,
    a: String,
    b: String,
    generator: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Answers {
    multiple_2: String,
    multiple_3: String,
    multiple_6: String,
    multiple_11: String,
    multiple_22: String,
    multiple_33: String,
    multiple_66: String,
    negative_generator: String,
    reduction_input: String,
    reduction_expected: String,
    field_encodings: Vec<FieldEncoding>,
    leading_zero_scalar: String,
    leading_zero_element: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldEncoding {
    input: String,
    expected: String,
}

fn vectors() -> Vec<Vector> {
    let file: Vectors = serde_json::from_str(include_str!("prime_groups/known_answers.json"))
        .expect("public fixtures");
    assert_eq!(file.schema_version, 1);
    assert_eq!(file.sources.len(), 4);
    assert_eq!(file.groups.len(), 10);
    file.groups
}

fn group(name: &str) -> PrimeGroup {
    match name {
        "Rfc5114Dh1024_160" => PrimeGroup::Rfc5114Dh1024_160,
        "Rfc5114Dh2048_224" => PrimeGroup::Rfc5114Dh2048_224,
        "Rfc5114Dh2048_256" => PrimeGroup::Rfc5114Dh2048_256,
        "NistP256" => PrimeGroup::NistP256,
        "BrainpoolP256r1" => PrimeGroup::BrainpoolP256r1,
        "BrainpoolP320r1" => PrimeGroup::BrainpoolP320r1,
        "NistP384" => PrimeGroup::NistP384,
        "BrainpoolP384r1" => PrimeGroup::BrainpoolP384r1,
        "BrainpoolP512r1" => PrimeGroup::BrainpoolP512r1,
        "NistP521" => PrimeGroup::NistP521,
        _ => unreachable_fixture(),
    }
}

#[allow(clippy::panic)]
fn unreachable_fixture() -> PrimeGroup {
    panic!("unknown fixture domain")
}

fn decode(value: &str) -> Vec<u8> {
    hex::decode(value).expect("public hex fixture")
}

fn small(group: PrimeGroup, value: u8) -> GroupScalar {
    let mut bytes = vec![0; group.scalar_len()];
    *bytes.last_mut().expect("nonempty scalar") = value;
    group.scalar(&bytes).expect("small scalar")
}

fn assert_error<T>(result: Result<T, CryptoError>, expected: CryptoError) {
    assert_eq!(result.err(), Some(expected));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn standard_parameters_and_generators_match_independent_fixtures() {
    for row in vectors() {
        let group = group(&row.group);
        assert_eq!(group.modulus(), decode(&row.domain.p));
        assert_eq!(group.order(), decode(&row.domain.q));
        assert_eq!(group.is_elliptic_curve(), !row.domain.a.is_empty());
        assert_eq!(row.domain.a.is_empty(), row.domain.b.is_empty());
        if let Some((a, b)) = group.curve_coefficients() {
            assert_eq!(a, decode(&row.domain.a));
            assert_eq!(b, decode(&row.domain.b));
        }
        assert_eq!(
            group.standard_generator_encoding(),
            decode(&row.domain.generator)
        );
        let generator = group.generator().expect("standard generator");
        assert_eq!(generator.group(), group);
        assert_eq!(generator.encoding(), decode(&row.domain.generator));
        assert_eq!(generator.encoding().len(), group.element_len());
        assert_eq!(
            small(group, 1)
                .public_element()
                .expect("one times generator")
                .encoding(),
            generator.encoding()
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn full_point_multiplication_and_agreement_match_independent_answers() {
    for row in vectors() {
        let group = group(&row.group);
        let two = small(group, 2);
        let three = small(group, 3);
        let a = two.public_element().expect("public A");
        let b = three.public_element().expect("public B");
        assert_eq!(a.encoding(), decode(&row.answers.multiple_2));
        assert_eq!(b.encoding(), decode(&row.answers.multiple_3));
        let shared = two.multiply(&b).expect("agreement");
        assert_eq!(shared.encoding(), decode(&row.answers.multiple_6));
        assert_eq!(
            shared.encoding(),
            three.multiply(&a).expect("reverse agreement").encoding()
        );
        let secret = shared.agreement_secret().expect("agreement encoding");
        assert_eq!(secret.expose_secret().len(), group.field_len());
        if group.is_elliptic_curve() {
            assert_eq!(
                secret.expose_secret(),
                &decode(&row.answers.multiple_6)[1..=group.field_len()]
            );
        } else {
            assert_eq!(secret.expose_secret(), shared.encoding());
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn supplied_base_and_linear_combination_match_independent_answers() {
    for row in vectors() {
        let group = group(&row.group);
        let generator = group.generator().expect("generator");
        let offset = group
            .element(&decode(&row.answers.multiple_6))
            .expect("offset");
        let mapped = group
            .linear_combination(&[5], &generator, &offset)
            .expect("linear combination");
        assert_eq!(mapped.encoding(), decode(&row.answers.multiple_11));
        let a = small(group, 2).multiply(&mapped).expect("supplied base A");
        let b = small(group, 3).multiply(&mapped).expect("supplied base B");
        assert_eq!(a.encoding(), decode(&row.answers.multiple_22));
        assert_eq!(b.encoding(), decode(&row.answers.multiple_33));
        let secret = small(group, 2).multiply(&b).expect("mapped agreement");
        assert_eq!(secret.encoding(), decode(&row.answers.multiple_66));
        assert_eq!(
            secret.encoding(),
            small(group, 3)
                .multiply(&a)
                .expect("reverse mapped agreement")
                .encoding()
        );
        assert_eq!(
            group
                .linear_combination(&[0], &generator, &offset)
                .expect("zero mapping scalar")
                .encoding(),
            offset.encoding()
        );
        assert_eq!(
            group
                .linear_combination(group.order(), &generator, &offset)
                .expect("reduced zero mapping scalar")
                .encoding(),
            offset.encoding()
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn field_reduction_and_encoding_match_independent_answers() {
    for row in vectors() {
        let group = group(&row.group);
        let reduced = group
            .reduce_to_field(&decode(&row.answers.reduction_input))
            .expect("field reduction");
        assert_eq!(
            reduced.expose_secret(),
            decode(&row.answers.reduction_expected)
        );
        for encoding in row.answers.field_encodings {
            let encoded = group
                .encode_field(&decode(&encoding.input))
                .expect("field encoding");
            assert_eq!(encoded.encoding(), decode(&encoding.expected));
            let public = small(group, 2)
                .multiply(&encoded)
                .expect("encoded supplied base");
            group
                .element(public.encoding())
                .expect("encoded public subgroup element");
        }
        assert_error(
            group.reduce_to_field(&[]),
            CryptoError::PRIMITIVE_INVALID_LENGTH,
        );
        assert_error(
            group.reduce_to_field(&[0; 513]),
            CryptoError::PRIMITIVE_INVALID_LENGTH,
        );
        assert_error(
            group.encode_field(&[]),
            CryptoError::PRIMITIVE_INVALID_LENGTH,
        );
        assert_error(
            group.encode_field(&vec![0; group.field_len()]),
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        );
        assert_error(
            group.encode_field(group.modulus()),
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        );
        let mut one = vec![0; group.field_len()];
        *one.last_mut().expect("nonempty field") = 1;
        assert_error(
            group.encode_field(&one),
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn agreement_encoding_preserves_leading_zero_bytes() {
    for row in vectors() {
        let group = group(&row.group);
        let scalar = group
            .scalar(&decode(&row.answers.leading_zero_scalar))
            .expect("leading zero scalar");
        let element = scalar.public_element().expect("leading zero element");
        assert_eq!(
            element.encoding(),
            decode(&row.answers.leading_zero_element)
        );
        let secret = element.agreement_secret().expect("leading zero agreement");
        assert_eq!(secret.expose_secret().first(), Some(&0));
        assert_eq!(secret.expose_secret().len(), group.field_len());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn scalar_bounds_identity_and_domain_binding_are_enforced() {
    for row in vectors() {
        let group = group(&row.group);
        assert_error(group.scalar(&[]), CryptoError::PRIMITIVE_INVALID_LENGTH);
        assert_error(
            group.scalar(&vec![0; group.scalar_len()]),
            CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY,
        );
        assert_error(
            group.scalar(group.order()),
            CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY,
        );
        assert_error(
            group.scalar(&vec![255; group.scalar_len()]),
            CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY,
        );
        let generator = group.generator().expect("generator");
        let mut q_minus_one = group.order().to_vec();
        *q_minus_one.last_mut().expect("nonempty order") -= 1;
        let negative = group
            .scalar(&q_minus_one)
            .expect("maximum valid scalar")
            .public_element()
            .expect("negative generator");
        assert_eq!(negative.encoding(), decode(&row.answers.negative_generator));
        assert_error(
            group.linear_combination(&q_minus_one, &generator, &generator),
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        );
        let other = if group == PrimeGroup::NistP256 {
            PrimeGroup::BrainpoolP256r1
        } else {
            PrimeGroup::NistP256
        };
        assert_error(
            small(group, 2).multiply(&other.generator().expect("other generator")),
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        );
        assert_error(
            group.linear_combination(
                &[1],
                &generator,
                &other.generator().expect("other generator"),
            ),
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn noncanonical_offcurve_and_wrong_subgroup_elements_are_rejected() {
    for row in vectors() {
        let group = group(&row.group);
        assert_error(group.element(&[]), CryptoError::PRIMITIVE_INVALID_LENGTH);
        assert_error(
            group.element(&vec![0; group.element_len()]),
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        );
        if group.is_elliptic_curve() {
            let mut bytes = vec![0; group.element_len()];
            bytes[0] = 4;
            assert_error(
                group.element(&bytes),
                CryptoError::PRIMITIVE_INVALID_PARAMETER,
            );
            bytes[1..=group.field_len()].copy_from_slice(group.modulus());
            assert_error(
                group.element(&bytes),
                CryptoError::PRIMITIVE_INVALID_PARAMETER,
            );
            let mut generator = decode(&row.domain.generator);
            generator[0] = 6;
            assert_error(
                group.element(&generator),
                CryptoError::PRIMITIVE_INVALID_PARAMETER,
            );
        } else {
            assert_error(
                group.element(group.modulus()),
                CryptoError::PRIMITIVE_INVALID_PARAMETER,
            );
            let mut value = vec![0; group.field_len()];
            *value.last_mut().expect("nonempty field") = 1;
            assert_error(
                group.element(&value),
                CryptoError::PRIMITIVE_INVALID_PARAMETER,
            );
            *value.last_mut().expect("nonempty field") = 2;
            assert_error(
                group.element(&value),
                CryptoError::PRIMITIVE_INVALID_PARAMETER,
            );
        }
    }
}

struct FixedRng {
    calls: usize,
    value: u8,
    fail: bool,
}
impl KeyRng for FixedRng {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        self.calls += 1;
        destination.fill(0);
        if self.fail {
            return Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE);
        }
        *destination.last_mut().expect("fixed scalar width") = self.value;
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn entropy_failures_and_rejection_are_bounded_for_every_domain() {
    for row in vectors() {
        let group = group(&row.group);
        let mut rng = FixedRng {
            calls: 0,
            value: 0,
            fail: false,
        };
        assert_error(
            group.random_scalar(&mut rng),
            CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE,
        );
        assert_eq!(rng.calls, 128);
        rng = FixedRng {
            calls: 0,
            value: 0,
            fail: true,
        };
        assert_error(
            group.random_scalar(&mut rng),
            CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE,
        );
        assert_eq!(rng.calls, 1);
        rng = FixedRng {
            calls: 0,
            value: 2,
            fail: false,
        };
        let scalar = group.random_scalar(&mut rng).expect("injected scalar");
        assert_eq!(rng.calls, 1);
        assert_eq!(scalar.group(), group);
        assert_eq!(
            scalar
                .public_element()
                .expect("random scalar public")
                .encoding(),
            decode(&row.answers.multiple_2)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn secret_owners_have_destruction_contracts() {
    fn protected<T: ZeroizeOnDrop>() {}
    protected::<GroupScalar>();
    protected::<reallyme_crypto::prime_groups::GroupElement>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn canonical_entropy_errors_are_not_collapsed() {
    struct Failure;
    impl KeyRng for Failure {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(0xa5);
            Err(CryptoError::BACKEND_INVALID_STATE)
        }
    }
    assert_eq!(
        PrimeGroup::NistP256.random_scalar(&mut Failure).err(),
        Some(CryptoError::BACKEND_INVALID_STATE)
    );
}
