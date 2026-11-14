// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{Algorithm, CryptoError};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPublicKeyFormatRequest, CryptoPublicKeyFormatResult, PublicKeyFormatOperation,
};

/// Invoke only the named existing helper, retaining its validation strength.
/// Absent algorithms, zero/unknown operations and disabled lanes fail closed.
/// Encoded outputs and affine coordinates remain distinct protected owners.
pub fn transform_public_key(
    request: &CryptoPublicKeyFormatRequest,
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    let identifier = request
        .algorithm
        .as_option()
        .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
    let algorithm =
        Algorithm::try_from(identifier).map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
    let operation = request
        .operation
        .as_known()
        .filter(|value| *value != PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_UNSPECIFIED)
        .ok_or(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
    // Selector validation still applies when every format provider is disabled;
    // only feature-selected handlers need the validated operation value.
    let _ = operation;
    // Identity validation is independent of an execution lane in the Ed25519
    // leaf. Its subgroup/canonical-encoding policy must not become a mere
    // length check when reached through this standalone format contract.
    #[cfg(feature = "ed25519")]
    if algorithm == Algorithm::Ed25519
        && operation == PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_VALIDATE_IDENTITY
    {
        crypto_ed25519::validate_public_key_identity(&request.public_key)?;
        return super::encoded(&request.public_key);
    }
    #[cfg(any(feature = "native", feature = "wasm"))]
    match algorithm {
        Algorithm::Ed25519 => {
            #[cfg(feature = "ed25519")]
            {
                ed25519(operation, &request.public_key)
            }
            #[cfg(not(feature = "ed25519"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::X25519 => {
            #[cfg(feature = "x25519")]
            {
                x25519(operation, &request.public_key)
            }
            #[cfg(not(feature = "x25519"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                p256(operation, &request.public_key)
            }
            #[cfg(not(feature = "p256"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                p384(operation, &request.public_key)
            }
            #[cfg(not(feature = "p384"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                p521(operation, &request.public_key)
            }
            #[cfg(not(feature = "p521"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "secp256k1")]
            {
                secp256k1(operation, &request.public_key)
            }
            #[cfg(not(feature = "secp256k1"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::MlDsa44 => {
            #[cfg(feature = "ml-dsa-44")]
            {
                super::public_key_pq::ml_dsa_44(operation, &request.public_key)
            }
            #[cfg(not(feature = "ml-dsa-44"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::MlDsa65 => {
            #[cfg(feature = "ml-dsa-65")]
            {
                super::public_key_pq::ml_dsa_65(operation, &request.public_key)
            }
            #[cfg(not(feature = "ml-dsa-65"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::MlDsa87 => {
            #[cfg(feature = "ml-dsa-87")]
            {
                super::public_key_pq::ml_dsa_87(operation, &request.public_key)
            }
            #[cfg(not(feature = "ml-dsa-87"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                super::public_key_pq::ml_kem_512(operation, &request.public_key)
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                super::public_key_pq::ml_kem_768(operation, &request.public_key)
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                super::public_key_pq::ml_kem_1024(operation, &request.public_key)
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::SlhDsaSha2_128s => {
            #[cfg(feature = "slh-dsa")]
            {
                super::public_key_pq::slh_dsa(operation, &request.public_key)
            }
            #[cfg(not(feature = "slh-dsa"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
        Algorithm::XWing768 => {
            #[cfg(feature = "x-wing")]
            {
                x_wing(operation, &request.public_key)
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
    }
    #[cfg(not(any(feature = "native", feature = "wasm")))]
    {
        let _ = (algorithm, operation);
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

#[cfg(all(feature = "ed25519", any(feature = "native", feature = "wasm")))]
fn ed25519(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => {
            let value = zeroize::Zeroizing::new(crypto_ed25519::encode_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value = zeroize::Zeroizing::new(crypto_ed25519::decode_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT => {
            super::encoded(crypto_ed25519::assert_public_key(public_key)?)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "x25519", any(feature = "native", feature = "wasm")))]
fn x25519(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => {
            let value = zeroize::Zeroizing::new(crypto_x25519::encode_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value = zeroize::Zeroizing::new(crypto_x25519::decode_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT => {
            super::encoded(crypto_x25519::assert_public_key(public_key)?)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "p256", any(feature = "native", feature = "wasm")))]
fn p256(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS => {
            let value = zeroize::Zeroizing::new(crypto_p256::compress_p256(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS => {
            let value = zeroize::Zeroizing::new(crypto_p256::decompress_p256(public_key)?);
            super::encoded(&value)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "p384", any(feature = "native", feature = "wasm")))]
fn p384(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS => {
            let value = zeroize::Zeroizing::new(crypto_p384::compress_p384(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS => {
            let value = zeroize::Zeroizing::new(crypto_p384::decompress_p384(public_key)?);
            super::encoded(&value)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "p521", any(feature = "native", feature = "wasm")))]
fn p521(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_COMPRESS => {
            let value = zeroize::Zeroizing::new(crypto_p521::compress_p521(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS => {
            let value = zeroize::Zeroizing::new(crypto_p521::decompress_p521(public_key)?);
            super::encoded(&value)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "secp256k1", any(feature = "native", feature = "wasm")))]
fn secp256k1(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE => {
            let value =
                zeroize::Zeroizing::new(crypto_secp256k1::encode_secp256k1_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value =
                zeroize::Zeroizing::new(crypto_secp256k1::decode_secp256k1_public_key(public_key)?);
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ASSERT => {
            super::encoded(crypto_secp256k1::assert_secp256k1_public_key(public_key)?)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_BIP340_ENCODE => {
            let value = zeroize::Zeroizing::new(
                crypto_secp256k1::encode_bip340_schnorr_public_key(public_key)?,
            );
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_BIP340_DECODE => {
            let value = zeroize::Zeroizing::new(
                crypto_secp256k1::decode_bip340_schnorr_public_key(public_key)?,
            );
            super::encoded(&value)
        }
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECOMPRESS => {
            let value = zeroize::Zeroizing::new(crypto_secp256k1::decompress_secp256k1_public_key(
                public_key,
            )?);
            affine(&value.0, &value.1)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "x-wing", any(feature = "native", feature = "wasm")))]
fn x_wing(
    operation: PublicKeyFormatOperation,
    public_key: &[u8],
) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    match operation {
        // These C helper semantics are a fixed-length validating copy, not the
        // deeper ML-KEM encapsulation-key validation path.
        PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_ENCODE
        | PublicKeyFormatOperation::PUBLIC_KEY_FORMAT_OPERATION_DECODE => {
            let value =
                zeroize::Zeroizing::new(crate::operations::key_encoding::copy_fixed_public_key(
                    public_key,
                    crypto_x_wing::X_WING_768_PUBLIC_KEY_LEN,
                )?);
            super::encoded(&value)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

#[cfg(all(feature = "secp256k1", any(feature = "native", feature = "wasm")))]
fn affine(x: &[u8], y: &[u8]) -> Result<CryptoPublicKeyFormatResult, CryptoError> {
    use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_public_key_format_result::Representation;
    use crate::native_contract_support::copy_bytes;
    let mut output = CryptoPublicKeyFormatResult {
        representation: Some(Representation::Affine(Box::default())),
    };
    match output.representation.as_mut() {
        Some(Representation::Affine(value)) => {
            copy_bytes(&mut value.x, x)?;
            copy_bytes(&mut value.y, y)?;
        }
        _ => return Err(CryptoError::BACKEND_INVALID_STATE),
    }
    Ok(output)
}
