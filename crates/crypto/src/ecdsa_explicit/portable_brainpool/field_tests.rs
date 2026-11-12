// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::unwrap_used)]

use elliptic_curve::{
    bigint::{CheckedAdd, CheckedSub, NonZero, U384, U512},
    ff::PrimeField,
    hazmat::FieldArithmetic,
    ops::{BatchInvert, Reduce},
    scalar::{FromUintUnchecked, IsHigh},
    Curve, CurveArithmetic,
};

use super::{bp320::BrainpoolP320r1, bp512::BrainpoolP512r1};

type Base320 = <BrainpoolP320r1 as FieldArithmetic>::FieldElement;
type Scalar320 = <BrainpoolP320r1 as CurveArithmetic>::Scalar;
type Base512 = <BrainpoolP512r1 as FieldArithmetic>::FieldElement;
type Scalar512 = <BrainpoolP512r1 as CurveArithmetic>::Scalar;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bp320_field_representation_and_roots() {
    assert_field_invariants::<Base320>(320, 40, 5);
    assert_full_generator_order::<Base320>(&[
        ("2", 1),
        ("11", 3),
        ("13", 2),
        ("59", 1),
        ("196907", 1),
        ("146208281456251399783", 1),
        (
            "2307908307480288228542246803936276549862379769663891118114524423",
            1,
        ),
    ]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bp512_field_representation_and_roots() {
    assert_field_invariants::<Base512>(512, 64, 2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bp320_scalar_generator_has_full_order() {
    assert_field_invariants::<Scalar320>(320, 40, 6);
    assert_full_generator_order::<Scalar320>(&[
        ("2", 4),
        ("5", 1),
        ("7", 1),
        ("13", 1),
        ("89", 1),
        ("317", 1),
        ("28661", 1),
        (
            "299589410500344960818634453344053290288849906371853185689121682914766027672438458623",
            1,
        ),
    ]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bp512_scalar_generator_has_full_order() {
    assert_field_invariants::<Scalar512>(512, 64, 7);
    assert_full_generator_order::<Scalar512>(&[
        ("2", 3), ("3", 1), ("41", 1), ("1559", 1), ("4391", 1), ("14557", 1),
        ("33278821", 1), ("56951731", 1), ("82441673", 1), ("447825179", 1),
        ("55886090402833", 1),
        ("23337925407708917343269873493319607638879341485914224746228038546474382183428298476287118961279", 1),
    ]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bp320_padded_storage_reduction_preserves_forty_byte_values() {
    // The storage integer is wider than the external scalar. Exercise both
    // reduction entry points above the subgroup order and at the storage max.
    let modulus =
        Option::<NonZero<U384>>::from(NonZero::new(*BrainpoolP320r1::ORDER.as_ref())).unwrap();
    let bytes = elliptic_curve::FieldBytes::<BrainpoolP320r1>::from([0xff; 40]);
    let mut storage_bytes = [0; U384::BYTES];
    let offset = storage_bytes.len().checked_sub(bytes.len()).unwrap();
    storage_bytes[offset..].copy_from_slice(bytes.as_slice());
    let integer = U384::from_be_slice(&storage_bytes);
    let reduced_bytes = <Scalar320 as Reduce<_>>::reduce(&bytes);
    assert_eq!(reduced_bytes.to_canonical(), integer.rem(&modulus));
    let reduced_storage = <Scalar320 as Reduce<U384>>::reduce(&U384::MAX);
    assert_eq!(reduced_storage.to_canonical(), U384::MAX.rem(&modulus));
    assert_eq!(reduced_bytes.to_repr().len(), 40);
    assert_eq!(reduced_storage.to_repr().len(), 40);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn scalar_conversion_and_high_s_boundaries_are_exact() {
    macro_rules! check {
        ($curve:ty, $scalar:ty, $uint:ty) => {{
            let order = <$curve>::ORDER;
            let half = order.as_ref().shr_vartime(1);
            let above_half = Option::<$uint>::from(half.checked_add(&<$uint>::ONE)).unwrap();
            let last = Option::<$uint>::from(order.as_ref().checked_sub(&<$uint>::ONE)).unwrap();
            for (integer, high) in [
                (<$uint>::ZERO, false),
                (<$uint>::ONE, false),
                (half, false),
                (above_half, true),
                (last, true),
            ] {
                let scalar = <$scalar as FromUintUnchecked>::from_uint_unchecked(integer);
                assert_eq!(scalar.to_canonical(), integer);
                assert_eq!(bool::from(scalar.is_high()), high);
            }
        }};
    }
    check!(BrainpoolP320r1, Scalar320, U384);
    check!(BrainpoolP512r1, Scalar512, U512);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn base_field_batch_inversion_handles_zero_and_empty_inputs() {
    assert_batch_inversion::<Base320>();
    assert_batch_inversion::<Base512>();
}

fn assert_batch_inversion<F: PrimeField + BatchInvert>() {
    let original = [F::from(2), F::ZERO, F::from(3), F::from(4)];
    let mut elements = original;
    let mut scratch = [F::ZERO; 4];
    let product_inverse = F::batch_invert_in_place(&mut elements, &mut scratch);
    assert_eq!(product_inverse * F::from(24), F::ONE);
    for (element, inverse) in original.iter().zip(elements) {
        if *element == F::ZERO {
            assert_eq!(inverse, F::ZERO);
        } else {
            assert_eq!(*element * inverse, F::ONE);
        }
    }
    assert_eq!(F::batch_invert_in_place(&mut [], &mut []), F::ONE);
    let mut zeros = [F::ZERO; 4];
    assert_eq!(F::batch_invert_in_place(&mut zeros, &mut scratch), F::ONE);
    assert_eq!(zeros, [F::ZERO; 4]);
}

fn assert_field_invariants<F: PrimeField>(bits: u32, width: usize, generator: u64) {
    assert_eq!(F::NUM_BITS, bits);
    assert_eq!(F::CAPACITY, bits.checked_sub(1).unwrap());
    assert_eq!(F::ZERO.to_repr().as_ref().len(), width);
    assert_eq!(F::MULTIPLICATIVE_GENERATOR, F::from(generator));
    assert_eq!(F::ROOT_OF_UNITY * F::ROOT_OF_UNITY_INV, F::ONE);
    assert_eq!(F::from(2) * F::TWO_INV, F::ONE);

    let order = field_order::<F>();
    let odd_order = order.shr_vartime(F::S);
    let two_power = U512::ONE.shl_vartime(F::S);
    assert_eq!(pow(F::ROOT_OF_UNITY, two_power), F::ONE);
    assert_ne!(pow(F::ROOT_OF_UNITY, two_power.shr_vartime(1)), F::ONE);
    assert_eq!(
        pow(F::MULTIPLICATIVE_GENERATOR, odd_order),
        F::ROOT_OF_UNITY
    );
    assert_eq!(pow(F::MULTIPLICATIVE_GENERATOR, two_power), F::DELTA);
    assert_eq!(pow(F::DELTA, odd_order), F::ONE);
    assert!(bool::from(F::MULTIPLICATIVE_GENERATOR.sqrt().is_none()));

    // Both full-width encodings and padded 320-bit storage must preserve the
    // canonical field boundary. The modulus itself is never a valid element.
    let modulus = hex::decode(F::MODULUS).unwrap();
    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(&modulus);
    assert!(bool::from(F::from_repr(repr).is_none()));
    for value in 0..128_u64 {
        let element = F::from(value);
        assert_eq!(F::from_repr(element.to_repr()).unwrap(), element);
        let root = element.square().sqrt().unwrap();
        assert_eq!(root.square(), element.square());
        if value == 0 {
            assert!(bool::from(element.invert().is_none()));
        } else {
            assert_eq!(element * element.invert().unwrap(), F::ONE);
        }
    }
}

fn assert_full_generator_order<F: PrimeField>(factors: &[(&str, u32)]) {
    let order = field_order::<F>();
    let mut product = U512::ONE;
    // These complete prime factorizations were checked independently. Checking
    // every distinct prime divisor distinguishes a primitive root from merely
    // a quadratic nonresidue, which would not meet the PrimeField contract.
    for (decimal, multiplicity) in factors {
        let prime = U512::from_str_radix_vartime(decimal, 10).unwrap();
        let divisor = Option::<NonZero<U512>>::from(NonZero::new(prime)).unwrap();
        let (exponent, remainder) = order.div_rem(&divisor);
        assert_eq!(remainder, U512::ZERO);
        assert_ne!(pow(F::MULTIPLICATIVE_GENERATOR, exponent), F::ONE);
        for _ in 0..*multiplicity {
            product = Option::<U512>::from(product.checked_mul(&prime)).unwrap();
        }
    }
    assert_eq!(product, order);
    assert_eq!(pow(F::MULTIPLICATIVE_GENERATOR, order), F::ONE);
}

fn field_order<F: PrimeField>() -> U512 {
    let modulus = U512::from_str_radix_vartime(F::MODULUS, 16).unwrap();
    Option::<U512>::from(modulus.checked_sub(&U512::ONE)).unwrap()
}

fn pow<F: PrimeField>(element: F, exponent: U512) -> F {
    // ff uses u64 exponent words on both 32-bit and 64-bit runtime lanes.
    let mut words = [0_u64; 8];
    for (word, bytes) in words
        .iter_mut()
        .zip(exponent.to_le_bytes().as_chunks::<8>().0)
    {
        *word = u64::from_le_bytes(*bytes);
    }
    element.pow_vartime(words)
}
