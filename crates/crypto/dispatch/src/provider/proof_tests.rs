// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, Enumeration};
use crypto_core::{Algorithm, CryptoError};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoKeyAlgorithmIdentifier, KeyAlgorithm, ProviderDecisionRequest,
    ProviderOperation as ProtoOperation,
};
use zeroize::Zeroizing;

use super::{FallbackPolicy, ProviderDecision, ProviderOperation};
use crate::{derive_keypair, derive_shared_secret, generate_keypair, kem_decapsulate};
use crate::{kem_encapsulate, sign, verify};

const UNSUPPORTED: CryptoError = CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM;

#[kani::proof]
fn provider_query_validates_raw_operation_and_key_ids() {
    let operation_id: i32 = kani::any();
    let key_id: i32 = kani::any();
    let request = ProviderDecisionRequest {
        operation: EnumValue::from(operation_id),
        algorithm: EnumValue::from(key_id),
    };
    let result = ProviderDecision::try_from(&request);
    let known_operation = matches!(ProtoOperation::from_i32(operation_id), Some(operation)
        if operation != ProtoOperation::PROVIDER_OPERATION_UNSPECIFIED);
    let known_key = matches!(KeyAlgorithm::from_i32(key_id), Some(key)
        if key != KeyAlgorithm::KEY_ALGORITHM_UNSPECIFIED);

    if known_operation && known_key {
        let Ok(decision) = result else {
            kani::assert(
                false,
                "known IDs must yield a decision for the requested route",
            );
            return;
        };
        assert_eq!(
            ProtoOperation::from(decision.operation).to_i32(),
            operation_id
        );
        assert_eq!(KeyAlgorithm::from(decision.algorithm).to_i32(), key_id);
        assert_eq!(decision.fallback, FallbackPolicy::Prohibited);
        kani::cover!(decision.is_selected(), "compiled Ed25519 route selected");
        kani::cover!(
            !decision.is_selected(),
            "known but unsupported route rejected"
        );
    } else {
        let expected = if known_operation {
            UNSUPPORTED
        } else {
            CryptoError::PRIMITIVE_INVALID_PARAMETER
        };
        assert_eq!(result, Err(expected));
    }
}

fn unexpected_generate() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    kani::assert(false, "a rejected key ID reached Ed25519 generation");
    Err(UNSUPPORTED)
}

fn unexpected_derive(_secret: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    kani::assert(false, "a rejected key ID reached Ed25519 derivation");
    Err(UNSUPPORTED)
}

fn unexpected_sign(_secret: &[u8], _message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    kani::assert(false, "a rejected key ID reached Ed25519 signing");
    Err(UNSUPPORTED)
}

fn unexpected_verify(
    _public: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), CryptoError> {
    kani::assert(false, "a rejected key ID reached Ed25519 verification");
    Err(UNSUPPORTED)
}

#[kani::proof]
#[kani::stub(<crate::algorithms::ed25519::Ed25519Algo as crate::traits::SignatureAlgorithm>::generate_keypair, unexpected_generate)]
#[kani::stub(<crate::algorithms::ed25519::Ed25519Algo as crate::traits::SignatureAlgorithm>::derive_keypair, unexpected_derive)]
#[kani::stub(<crate::algorithms::ed25519::Ed25519Algo as crate::traits::SignatureAlgorithm>::sign, unexpected_sign)]
#[kani::stub(<crate::algorithms::ed25519::Ed25519Algo as crate::traits::SignatureAlgorithm>::verify, unexpected_verify)]
fn restricted_native_dispatch_never_falls_back_to_ed25519() {
    // The policy-query harness covers IDs that do not convert to a key. Here
    // exercise every recognized key through the actual registry entry points.
    let key = CryptoKeyAlgorithmIdentifier {
        algorithm: EnumValue::from(kani::any::<i32>()),
    };
    let Ok(algorithm) = Algorithm::try_from(&key) else {
        return;
    };
    kani::cover!(algorithm == Algorithm::Ed25519, "compiled key ID");
    kani::cover!(algorithm == Algorithm::MlKem768, "known disabled key ID");

    if algorithm != Algorithm::Ed25519 {
        assert_eq!(generate_keypair(algorithm).err(), Some(UNSUPPORTED));
        assert_eq!(derive_keypair(algorithm, &[]).err(), Some(UNSUPPORTED));
        assert_eq!(sign(algorithm, &[], &[]).err(), Some(UNSUPPORTED));
        assert_eq!(verify(algorithm, &[], &[], &[]).err(), Some(UNSUPPORTED));
    }
    assert_eq!(
        derive_shared_secret(algorithm, &[], &[]).err(),
        Some(UNSUPPORTED)
    );
    assert_eq!(kem_encapsulate(algorithm, &[]).err(), Some(UNSUPPORTED));
    assert_eq!(
        kem_decapsulate(algorithm, &[], &[]).err(),
        Some(UNSUPPORTED)
    );

    // Even the single compiled key cannot be substituted into a KEM operation.
    assert!(super::require_provider(ProviderOperation::KemEncapsulate, algorithm).is_err());
}
