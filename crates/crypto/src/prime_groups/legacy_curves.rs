// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Only standard domain parameters and generic-engine trait bindings live here.
// All scalar/supplied-base operations keep using the existing guarded group
// boundary; registration does not change signature suites or strength policy.

// One parameter literal feeds both the backend and the public domain bytes.
// The macro supplies the same generic-engine bindings as the existing wider
// Brainpool domains; it introduces no field or point arithmetic implementation.
macro_rules! define_legacy_curve {
    (
        curve: $curve:ident, uint: $uint:ident, bytes: $bytes:ident,
        padding: $padding:literal,
        field: ($modulus:literal, $field_generator:literal),
        scalar: ($order:literal, $scalar_generator:literal),
        a: $a:literal, b: $b:literal,
        generator: ($x:literal, $y:literal)
    ) => {
        use elliptic_curve::{
            bigint::{$uint, Odd},
            consts::$bytes,
            hazmat::FieldArithmetic,
            point::PointCompression,
            Curve, CurveArithmetic, PrimeCurve, PrimeCurveArithmetic,
        };
        use field::FieldElement;
        use primeorder::{mul_backend, point_arithmetic, PrimeCurveParams};
        use scalar::Scalar;

        const ORDER_STORAGE_HEX: &str = concat!($padding, $order);
        const GENERATOR_BYTES: &[u8] = &hex_literal::hex! { "04" $x $y };

        pub(in crate::prime_groups) const DOMAIN: super::super::domain::Domain =
            super::super::domain::Domain {
                p: &hex_literal::hex!($modulus),
                q: &hex_literal::hex!($order),
                a: &hex_literal::hex!($a),
                b: &hex_literal::hex!($b),
                generator: GENERATOR_BYTES,
            };

        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
        pub struct $curve;
        impl Curve for $curve {
            type FieldBytesSize = $bytes;
            type Uint = $uint;
            const ORDER: Odd<$uint> = Odd::from_be_hex(ORDER_STORAGE_HEX);
        }
        impl PrimeCurve for $curve {}
        impl PointCompression for $curve {
            const COMPRESS_POINTS: bool = false;
        }
        impl CurveArithmetic for $curve {
            type AffinePoint = primeorder::AffinePoint<Self>;
            type ProjectivePoint = primeorder::ProjectivePoint<Self>;
            type Scalar = Scalar;
        }
        impl FieldArithmetic for $curve {
            type FieldElement = FieldElement;
        }
        impl PrimeCurveArithmetic for $curve {
            type CurveGroup = primeorder::ProjectivePoint<Self>;
        }
        impl PrimeCurveParams for $curve {
            type PointArithmetic = point_arithmetic::EquationAIsGeneric;
            type Backend = mul_backend::VariableOnly;
            const EQUATION_A: FieldElement = FieldElement::from_hex_vartime($a);
            const EQUATION_B: FieldElement = FieldElement::from_hex_vartime($b);
            const GENERATOR: (FieldElement, FieldElement) = (
                FieldElement::from_hex_vartime($x),
                FieldElement::from_hex_vartime($y),
            );
        }

        mod field {
            use super::$uint;
            use elliptic_curve::{
                ff::PrimeField,
                ops::BatchInvert,
                subtle::{Choice, ConstantTimeEq, CtOption},
            };
            use primefield::bigint::modular::ConstMontyParams;
            primefield::bigint::const_prime_monty_params!(
                FieldParams,
                $uint,
                concat!($padding, $modulus),
                $field_generator,
                "Standard legacy base-field parameters."
            );
            impl primefield::MontyFieldParams<{ $uint::LIMBS }> for FieldParams {
                type ByteSize = elliptic_curve::consts::$bytes;
                const BYTE_ORDER: primefield::ByteOrder = primefield::ByteOrder::BigEndian;
                const MODULUS_HEX: &'static str = $modulus;
                const T: $uint = primefield::compute_t(FieldParams::PARAMS.modulus().as_ref());
            }
            primefield::monty_field_element! {
                name: FieldElement, params: FieldParams, uint: $uint,
                doc: "Legacy base-field element."
            }
            primefield::monty_field_arithmetic! {
                name: FieldElement, params: FieldParams, uint: $uint
            }
            impl BatchInvert for FieldElement {}
        }

        mod scalar {
            use super::{$curve, $uint, ORDER_STORAGE_HEX};
            use elliptic_curve::{
                ff::PrimeField,
                scalar::{FromUintUnchecked, IsHigh},
                subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption},
            };
            use primefield::bigint::modular::ConstMontyParams;
            primefield::bigint::const_prime_monty_params!(
                ScalarParams,
                $uint,
                ORDER_STORAGE_HEX,
                $scalar_generator,
                "Standard legacy subgroup-order parameters."
            );
            impl primefield::MontyFieldParams<{ $uint::LIMBS }> for ScalarParams {
                type ByteSize = elliptic_curve::consts::$bytes;
                const BYTE_ORDER: primefield::ByteOrder = primefield::ByteOrder::BigEndian;
                const MODULUS_HEX: &'static str = $order;
                const T: $uint = primefield::compute_t(ScalarParams::PARAMS.modulus().as_ref());
            }
            primefield::monty_field_element! {
                name: Scalar, params: ScalarParams, uint: $uint,
                doc: "Legacy scalar-field element."
            }
            primefield::monty_field_arithmetic! {
                name: Scalar, params: ScalarParams, uint: $uint
            }
            impl elliptic_curve::ops::Reduce<$uint> for Scalar {
                fn reduce(value: &$uint) -> Self {
                    Self::from_uint_unchecked(*value)
                }
            }
            impl elliptic_curve::ops::Reduce<elliptic_curve::FieldBytes<$curve>> for Scalar {
                fn reduce(value: &elliptic_curve::FieldBytes<$curve>) -> Self {
                    Self::from_uint_unchecked(elliptic_curve::field::bytes_to_uint::<$curve>(value))
                }
            }
            elliptic_curve::scalar_impls!($curve, Scalar);
            primeorder::wnaf::impl_wnaf_size_for_scalar!(Scalar);
            impl AsRef<Scalar> for Scalar {
                fn as_ref(&self) -> &Self {
                    self
                }
            }
            impl FromUintUnchecked for Scalar {
                type Uint = $uint;
                fn from_uint_unchecked(value: Self::Uint) -> Self {
                    Self::from_uint_unchecked(value)
                }
            }
            impl IsHigh for Scalar {
                fn is_high(&self) -> Choice {
                    const HALF_ORDER: $uint = $uint::from_be_hex(ORDER_STORAGE_HEX).shr_vartime(1);
                    self.to_canonical().ct_gt(&HALF_ORDER)
                }
            }
        }
    };
}

pub(super) mod bp192;
pub(super) mod bp224;
pub(super) mod nistp192;
