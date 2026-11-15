// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::EnumValue;
use crypto_core::Algorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoKeyAlgorithmIdentifier, ProviderOperation as WireOperation,
};

#[cfg(all(feature = "wasm", feature = "secp256k1", not(feature = "native")))]
use super::{provider_decision_for_lane, ProviderLane};
use super::{FallbackPolicy, ProviderOperation};

fn symbolic_route() -> Option<(ProviderOperation, Algorithm)> {
    let raw_op = EnumValue::<WireOperation>::from(kani::any::<i32>());
    let raw_key = CryptoKeyAlgorithmIdentifier {
        algorithm: EnumValue::from(kani::any::<i32>()),
    };
    Some((
        ProviderOperation::try_from(raw_op).ok()?,
        Algorithm::try_from(&raw_key).ok()?,
    ))
}

#[cfg(all(feature = "wasm", feature = "secp256k1", not(feature = "native")))]
#[kani::proof]
fn reduced_wasm_policy_selects_only_reviewed_routes() {
    let Some((operation, algorithm)) = symbolic_route() else {
        return;
    };
    let selected = matches!(
        (algorithm, operation),
        (
            Algorithm::Secp256k1,
            ProviderOperation::GenerateKeyPair
                | ProviderOperation::Sign
                | ProviderOperation::Verify
        ) | (
            Algorithm::MlKem768,
            ProviderOperation::GenerateKeyPair
                | ProviderOperation::DeriveKeyPair
                | ProviderOperation::KemEncapsulate
                | ProviderOperation::KemDecapsulate
        )
    );
    let wasm = provider_decision_for_lane(operation, algorithm, ProviderLane::Wasm);
    assert_eq!(wasm.is_selected(), selected);
    assert_eq!(wasm.lane, ProviderLane::Wasm);
    assert_eq!(wasm.fallback, FallbackPolicy::Prohibited);
    assert!(!provider_decision_for_lane(operation, algorithm, ProviderLane::Native).is_selected());
    kani::cover!(
        selected && algorithm == Algorithm::Secp256k1,
        "WASM secp256k1 route"
    );
    kani::cover!(
        selected && algorithm == Algorithm::MlKem768,
        "WASM ML-KEM route"
    );
    kani::cover!(
        (algorithm, operation) == (Algorithm::Secp256k1, ProviderOperation::DeriveKeyPair)
            && !wasm.is_selected(),
        "WASM rejects secp256k1 key reconstruction"
    );
}

#[cfg(all(feature = "native", feature = "ml-dsa-65"))]
mod mixed_native {
    use super::{symbolic_route, FallbackPolicy, ProviderOperation};
    use buffa::EnumValue;
    use crypto_core::{Algorithm, CryptoError};
    use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoKeyAlgorithmIdentifier;
    use zeroize::Zeroizing;

    const SELECTED: CryptoError = CryptoError::PROVIDER_ACCESS_DENIED;
    const UNSUPPORTED: CryptoError = CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM;

    #[kani::proof]
    fn mixed_native_policy_distinguishes_signature_and_kem_routes() {
        let Some((operation, algorithm)) = symbolic_route() else {
            return;
        };
        let selected = matches!(
            (algorithm, operation),
            (
                Algorithm::MlDsa65,
                ProviderOperation::GenerateKeyPair
                    | ProviderOperation::DeriveKeyPair
                    | ProviderOperation::Sign
                    | ProviderOperation::Verify
            ) | (
                Algorithm::MlKem768,
                ProviderOperation::GenerateKeyPair
                    | ProviderOperation::DeriveKeyPair
                    | ProviderOperation::KemEncapsulate
                    | ProviderOperation::KemDecapsulate
            )
        );
        let decision = super::super::provider_decision(operation, algorithm);
        assert_eq!(decision.is_selected(), selected);
        assert_eq!(decision.fallback, FallbackPolicy::Prohibited);
    }

    fn sign(_key: &[u8], marker: &[u8]) -> Result<Vec<u8>, CryptoError> {
        assert_eq!(marker, [1]);
        Err(SELECTED)
    }

    fn decapsulate(marker: &[u8], _key: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        assert_eq!(marker, [1]);
        Err(SELECTED)
    }

    #[kani::proof]
    #[kani::stub(<crate::algorithms::ml_dsa_65::MlDsa65Algo as crate::traits::SignatureAlgorithm>::sign, sign)]
    #[kani::stub(crate::algorithms::ml_kem_768::MlKem768Algo::decapsulate, decapsulate)]
    fn mixed_registry_never_invokes_the_other_key_family() {
        let raw = CryptoKeyAlgorithmIdentifier {
            algorithm: EnumValue::from(kani::any::<i32>()),
        };
        let Ok(algorithm) = Algorithm::try_from(&raw) else {
            return;
        };
        let is_signing_key = algorithm == Algorithm::MlDsa65;
        let is_kem_key = algorithm == Algorithm::MlKem768;
        let signing = crate::sign(algorithm, &[], &[u8::from(is_signing_key)]).err();
        let kem = crate::kem_decapsulate(algorithm, &[u8::from(is_kem_key)], &[]).err();
        assert_eq!(
            signing,
            Some(if is_signing_key {
                SELECTED
            } else {
                UNSUPPORTED
            })
        );
        assert_eq!(kem, Some(if is_kem_key { SELECTED } else { UNSUPPORTED }));
        kani::cover!(
            signing == Some(SELECTED) && kem == Some(UNSUPPORTED),
            "signing only"
        );
        kani::cover!(
            kem == Some(SELECTED) && signing == Some(UNSUPPORTED),
            "decapsulation only"
        );
    }
}
