// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone adapters for existing public-key representation helpers.
//!
//! These functions preserve each leaf's validation strength and error policy.
//! They do not register executable root operations or select a fallback lane.

mod public_key;
#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "slh-dsa"
    )
))]
mod public_key_pq;
mod signature;

pub use public_key::transform_public_key;
pub use signature::{normalize_p256_signature, transcode_secp256k1_signature};

#[cfg(any(
    feature = "ed25519",
    all(
        any(feature = "native", feature = "wasm"),
        any(
            feature = "x25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "ml-kem-512",
            feature = "ml-kem-768",
            feature = "ml-kem-1024",
            feature = "slh-dsa",
            feature = "x-wing"
        )
    )
))]
fn encoded(
    bytes: &[u8],
) -> Result<
    crypto_proto::generated::proto::reallyme::crypto::v1::CryptoPublicKeyFormatResult,
    crypto_core::CryptoError,
> {
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        __buffa::oneof::crypto_public_key_format_result::Representation,
        CryptoPublicKeyFormatResult,
    };
    let mut output = CryptoPublicKeyFormatResult {
        representation: Some(Representation::Encoded(Box::default())),
        __buffa_unknown_fields: Default::default(),
    };
    match output.representation.as_mut() {
        Some(Representation::Encoded(value)) => {
            crate::native_contract_support::copy_bytes(&mut value.value, bytes)?
        }
        _ => return Err(crypto_core::CryptoError::BACKEND_INVALID_STATE),
    }
    Ok(output)
}

#[cfg(any(feature = "p256", feature = "ecdsa-explicit", feature = "secp256k1"))]
fn signature(
    bytes: &[u8],
) -> Result<
    crypto_proto::generated::proto::reallyme::crypto::v1::CryptoNativeSignatureResult,
    crypto_core::CryptoError,
> {
    let mut output =
        crypto_proto::generated::proto::reallyme::crypto::v1::CryptoNativeSignatureResult::default(
        );
    crate::native_contract_support::copy_bytes(&mut output.signature, bytes)?;
    Ok(output)
}

// Used for the NIST container import helper, which already returns compressed
// SEC1 bytes rather than the generic format helper's representation oneof.
#[cfg(all(feature = "ecdsa-explicit", feature = "native"))]
pub(crate) fn p256_public(
    bytes: &[u8],
) -> Result<
    crypto_proto::generated::proto::reallyme::crypto::v1::CryptoEcdsaPublicKey,
    crypto_core::CryptoError,
> {
    use buffa::MessageField;
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        CryptoEcdsaCurveIdentifier, CryptoEcdsaPublicKey, EcdsaCurve,
    };
    let mut output = CryptoEcdsaPublicKey {
        curve: MessageField::some(CryptoEcdsaCurveIdentifier {
            curve: EcdsaCurve::ECDSA_CURVE_NIST_P256.into(),
            __buffa_unknown_fields: Default::default(),
        }),
        sec1: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    crate::native_contract_support::copy_bytes(&mut output.sec1, bytes)?;
    Ok(output)
}
