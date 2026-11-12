// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// RFC 5639 section 3.5. Only domain parameters are defined here;
// field and complete point arithmetic use the existing generic implementations.
// A 384-bit storage width uses the existing array encoding implementation.
// The order remains exactly 320 bits; the external boundary retains 40-byte widths.
use elliptic_curve::{
    bigint::{Odd, U384},
    consts::U40,
    hazmat::FieldArithmetic,
    point::PointCompression,
    Curve, CurveArithmetic, PrimeCurve, PrimeCurveArithmetic,
};
use field::FieldElement;
use primeorder::{mul_backend, point_arithmetic, PrimeCurveParams};
use scalar::Scalar;

const ORDER_HEX: &str =
    "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
const ORDER_STORAGE_HEX: &str = "0000000000000000d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311";
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct BrainpoolP320r1;
impl Curve for BrainpoolP320r1 {
    type FieldBytesSize = U40;
    type Uint = U384;
    const ORDER: Odd<U384> = Odd::from_be_hex(ORDER_STORAGE_HEX);
}
impl PrimeCurve for BrainpoolP320r1 {}
impl PointCompression for BrainpoolP320r1 {
    const COMPRESS_POINTS: bool = false;
}
impl CurveArithmetic for BrainpoolP320r1 {
    type AffinePoint = primeorder::AffinePoint<Self>;
    type ProjectivePoint = primeorder::ProjectivePoint<Self>;
    type Scalar = Scalar;
}
impl FieldArithmetic for BrainpoolP320r1 {
    type FieldElement = FieldElement;
}
impl PrimeCurveArithmetic for BrainpoolP320r1 {
    type CurveGroup = primeorder::ProjectivePoint<Self>;
}
impl PrimeCurveParams for BrainpoolP320r1 {
    type PointArithmetic = point_arithmetic::EquationAIsGeneric;
    type Backend = mul_backend::VariableOnly;
    const EQUATION_A: FieldElement = FieldElement::from_hex_vartime(
        "3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4",
    );
    const EQUATION_B: FieldElement = FieldElement::from_hex_vartime(
        "520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6",
    );
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex_vartime(
            "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611",
        ),
        FieldElement::from_hex_vartime(
            "14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1",
        ),
    );
}
impl ecdsa::EcdsaCurve for BrainpoolP320r1 {
    const NORMALIZE_S: bool = false;
}
impl ecdsa::DigestAlgorithm for BrainpoolP320r1 {
    type Digest = sha2_backend::Sha384;
}

mod field {
    use super::U384;
    use elliptic_curve::{
        ff::PrimeField,
        ops::BatchInvert,
        subtle::{Choice, ConstantTimeEq, CtOption},
    };
    use primefield::bigint::modular::ConstMontyParams;
    primefield::bigint::const_prime_monty_params!(FieldParams, U384, "0000000000000000d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27", 5, "RFC 5639 base field parameters.");
    impl primefield::MontyFieldParams<{ U384::LIMBS }> for FieldParams {
        type ByteSize = elliptic_curve::consts::U40;
        const BYTE_ORDER: primefield::ByteOrder = primefield::ByteOrder::BigEndian;
        const MODULUS_HEX: &'static str =
            "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27";
        const T: U384 = primefield::compute_t(FieldParams::PARAMS.modulus().as_ref());
    }
    primefield::monty_field_element! { name: FieldElement, params: FieldParams, uint: U384, doc: "Base field element." }
    primefield::monty_field_arithmetic! { name: FieldElement, params: FieldParams, uint: U384 }
    impl BatchInvert for FieldElement {}
}
mod scalar {
    use super::{BrainpoolP320r1, ORDER_HEX, ORDER_STORAGE_HEX, U384};
    use elliptic_curve::{
        ff::PrimeField,
        scalar::{FromUintUnchecked, IsHigh},
        subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption},
    };
    use primefield::bigint::modular::ConstMontyParams;
    primefield::bigint::const_prime_monty_params!(
        ScalarParams,
        U384,
        ORDER_STORAGE_HEX,
        6,
        "RFC 5639 subgroup order parameters."
    );
    impl primefield::MontyFieldParams<{ U384::LIMBS }> for ScalarParams {
        type ByteSize = elliptic_curve::consts::U40;
        const BYTE_ORDER: primefield::ByteOrder = primefield::ByteOrder::BigEndian;
        const MODULUS_HEX: &'static str = ORDER_HEX;
        const T: U384 = primefield::compute_t(ScalarParams::PARAMS.modulus().as_ref());
    }
    primefield::monty_field_element! { name: Scalar, params: ScalarParams, uint: U384, doc: "Scalar field element." }
    primefield::monty_field_arithmetic! { name: Scalar, params: ScalarParams, uint: U384 }
    impl elliptic_curve::ops::Reduce<U384> for Scalar {
        fn reduce(value: &U384) -> Self {
            Self::from_uint_unchecked(*value)
        }
    }
    impl elliptic_curve::ops::Reduce<elliptic_curve::FieldBytes<BrainpoolP320r1>> for Scalar {
        fn reduce(value: &elliptic_curve::FieldBytes<BrainpoolP320r1>) -> Self {
            Self::from_uint_unchecked(elliptic_curve::field::bytes_to_uint::<BrainpoolP320r1>(
                value,
            ))
        }
    }
    elliptic_curve::scalar_impls!(BrainpoolP320r1, Scalar);
    primeorder::wnaf::impl_wnaf_size_for_scalar!(Scalar);
    impl AsRef<Scalar> for Scalar {
        fn as_ref(&self) -> &Self {
            self
        }
    }
    impl FromUintUnchecked for Scalar {
        type Uint = U384;
        fn from_uint_unchecked(uint: Self::Uint) -> Self {
            Self::from_uint_unchecked(uint)
        }
    }
    impl IsHigh for Scalar {
        fn is_high(&self) -> Choice {
            const HALF_ORDER: U384 = U384::from_be_hex(ORDER_STORAGE_HEX).shr_vartime(1);
            self.to_canonical().ct_gt(&HALF_ORDER)
        }
    }
}
