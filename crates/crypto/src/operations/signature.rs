// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic owner for raw-key signature operations.

use crypto_core::Algorithm;
use zeroize::Zeroizing;

use crate::operations::OperationError;
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

#[cfg(all(feature = "slh-dsa", any(feature = "native", feature = "wasm")))]
const SLH_DSA_SEED_COMPONENT_LEN: usize = crypto_slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN;
#[cfg(all(feature = "slh-dsa", any(feature = "native", feature = "wasm")))]
const SLH_DSA_DERIVE_INPUT_LEN: usize =
    crypto_core::contract_constants::operation_signature::SLH_DSA_DERIVE_INPUT_LEN;

/// Raw public/secret keypair returned by a signature key-management operation.
pub struct SignatureKeyPair {
    /// Public verification key bytes in the algorithm's canonical encoding.
    pub public_key: Vec<u8>,
    /// Secret signing key bytes. The buffer is wiped when dropped.
    pub secret_key: Zeroizing<Vec<u8>>,
}

/// Generates a raw keypair for a supported raw-key signature algorithm.
pub fn generate_key_pair(algorithm: Algorithm) -> Result<SignatureKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureKeyGeneration);
    ensure_supported_signature_algorithm(algorithm)?;
    if algorithm == Algorithm::SlhDsaSha2_128s {
        return generate_slh_dsa_sha2_128s_key_pair();
    }
    crypto_dispatch::generate_keypair(algorithm).map(signature_key_pair)
}

/// Reconstructs a raw keypair from seed or scalar material.
pub fn derive_key_pair(
    algorithm: Algorithm,
    secret_key: &[u8],
) -> Result<SignatureKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureKeyDerivation);
    ensure_supported_signature_algorithm(algorithm)?;
    if algorithm == Algorithm::SlhDsaSha2_128s {
        return derive_slh_dsa_sha2_128s_key_pair(secret_key);
    }
    crypto_dispatch::derive_keypair(algorithm, secret_key).map(signature_key_pair)
}

/// Signs `message` with raw secret material.
pub fn sign(
    algorithm: Algorithm,
    secret_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureSign);
    ensure_supported_signature_algorithm(algorithm)?;
    if algorithm == Algorithm::SlhDsaSha2_128s {
        return sign_slh_dsa_sha2_128s(secret_key, message);
    }
    crypto_dispatch::sign(algorithm, secret_key, message)
}

/// Verifies `signature` against `message` and `public_key`.
pub fn verify(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureVerify);
    ensure_supported_signature_algorithm(algorithm)?;
    if algorithm == Algorithm::SlhDsaSha2_128s {
        return verify_slh_dsa_sha2_128s(public_key, message, signature);
    }
    crypto_dispatch::verify(algorithm, public_key, message, signature)
}

/// Normalizes a canonical DER-encoded P-256 signature to low-S form.
#[cfg(feature = "p256")]
pub fn normalize_p256_ecdsa_der_low_s(signature: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureEncoding);
    crypto_p256::normalize_p256_ecdsa_der_low_s(signature)
}

/// Normalizes an exact 64-byte P-256 JOSE `r || s` signature to low-S form.
#[cfg(feature = "p256")]
pub fn normalize_p256_ecdsa_jose_low_s(
    signature: &[u8],
) -> Result<[u8; crypto_p256::P256_ECDSA_JOSE_SIGNATURE_LEN], OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureEncoding);
    crypto_p256::normalize_p256_ecdsa_jose_signature_low_s(signature)
}

/// Generates a BIP-340 keypair with an x-only public key.
pub fn generate_bip340_key_pair() -> Result<SignatureKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureKeyGeneration);
    #[cfg(all(feature = "secp256k1", any(feature = "native", feature = "wasm")))]
    {
        let key_pair = generate_key_pair(Algorithm::Secp256k1)?;
        let public_key = derive_bip340_public_key(&key_pair.secret_key)?;
        Ok(SignatureKeyPair {
            public_key,
            secret_key: key_pair.secret_key,
        })
    }

    #[cfg(not(all(feature = "secp256k1", any(feature = "native", feature = "wasm"))))]
    {
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

/// Reconstructs a BIP-340 keypair from a validated secp256k1 secret scalar.
pub fn derive_bip340_key_pair(secret_key: &[u8]) -> Result<SignatureKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureKeyDerivation);
    let public_key = derive_bip340_public_key(secret_key)?;
    Ok(SignatureKeyPair {
        public_key,
        secret_key: Zeroizing::new(secret_key.to_vec()),
    })
}

/// Derives a BIP-340 x-only public key from a secp256k1 secret scalar.
pub fn derive_bip340_public_key(secret_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureKeyDerivation);
    #[cfg(all(feature = "secp256k1", any(feature = "native", feature = "wasm")))]
    {
        crypto_secp256k1::derive_bip340_schnorr_public_key(secret_key)
    }

    #[cfg(not(all(feature = "secp256k1", any(feature = "native", feature = "wasm"))))]
    {
        let _ = secret_key;
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

/// Signs a 32-byte BIP-340 message with explicit 32-byte auxiliary randomness.
pub fn sign_bip340(
    secret_key: &[u8],
    message32: &[u8],
    aux_rand32: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureSign);
    #[cfg(all(feature = "secp256k1", any(feature = "native", feature = "wasm")))]
    {
        crypto_secp256k1::sign_bip340_schnorr(secret_key, message32, aux_rand32)
    }

    #[cfg(not(all(feature = "secp256k1", any(feature = "native", feature = "wasm"))))]
    {
        let _ = (secret_key, message32, aux_rand32);
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

/// Verifies a BIP-340 Schnorr signature over a 32-byte message.
pub fn verify_bip340(
    signature: &[u8],
    message32: &[u8],
    public_key_xonly: &[u8],
) -> Result<(), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureVerify);
    #[cfg(all(feature = "secp256k1", any(feature = "native", feature = "wasm")))]
    {
        crypto_secp256k1::verify_bip340_schnorr(signature, message32, public_key_xonly)
    }

    #[cfg(not(all(feature = "secp256k1", any(feature = "native", feature = "wasm"))))]
    {
        let _ = (signature, message32, public_key_xonly);
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

/// Verifies an RSASSA-PKCS1-v1_5 signature.
#[cfg(feature = "rsa")]
pub fn verify_rsa_pkcs1v15(
    public_key_der: &[u8],
    encoding: crypto_rsa::RsaPublicKeyDerEncoding,
    hash: crypto_rsa::RsaHash,
    message: &[u8],
    signature: &[u8],
) -> Result<(), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureVerify);
    crypto_rsa::verify_rsa_pkcs1v15(public_key_der, encoding, hash, message, signature)
}

/// Verifies an RSASSA-PSS signature with explicit message and MGF1 hashes.
#[cfg(feature = "rsa")]
pub fn verify_rsa_pss(
    public_key_der: &[u8],
    encoding: crypto_rsa::RsaPublicKeyDerEncoding,
    params: crypto_rsa::RsaPssParams,
    message: &[u8],
    signature: &[u8],
) -> Result<(), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureVerify);
    crypto_rsa::verify_rsa_pss(public_key_der, encoding, params, message, signature)
}

fn is_supported_signature_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::Ed25519
            | Algorithm::P256
            | Algorithm::P384
            | Algorithm::P521
            | Algorithm::Secp256k1
            | Algorithm::MlDsa44
            | Algorithm::MlDsa65
            | Algorithm::MlDsa87
            | Algorithm::SlhDsaSha2_128s
    )
}

fn ensure_supported_signature_algorithm(algorithm: Algorithm) -> Result<(), OperationError> {
    if is_supported_signature_algorithm(algorithm) {
        Ok(())
    } else {
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

fn generate_slh_dsa_sha2_128s_key_pair() -> Result<SignatureKeyPair, OperationError> {
    #[cfg(all(feature = "slh-dsa", any(feature = "native", feature = "wasm")))]
    {
        crypto_slh_dsa::generate_slh_dsa_sha2_128s_keypair().map(signature_key_pair)
    }

    #[cfg(not(all(feature = "slh-dsa", any(feature = "native", feature = "wasm"))))]
    {
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

fn derive_slh_dsa_sha2_128s_key_pair(
    secret_key: &[u8],
) -> Result<SignatureKeyPair, OperationError> {
    #[cfg(all(feature = "slh-dsa", any(feature = "native", feature = "wasm")))]
    {
        if secret_key.len() != SLH_DSA_DERIVE_INPUT_LEN {
            return Err(crypto_core::CryptoError::PRIMITIVE_INVALID_KEY);
        }
        let (sk_seed, rest) = secret_key.split_at(SLH_DSA_SEED_COMPONENT_LEN);
        let (sk_prf, pk_seed) = rest.split_at(SLH_DSA_SEED_COMPONENT_LEN);
        crypto_slh_dsa::derive_slh_dsa_sha2_128s_keypair(sk_seed, sk_prf, pk_seed)
            .map(signature_key_pair)
    }

    #[cfg(not(all(feature = "slh-dsa", any(feature = "native", feature = "wasm"))))]
    {
        let _ = secret_key;
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

fn sign_slh_dsa_sha2_128s(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, OperationError> {
    #[cfg(all(feature = "slh-dsa", any(feature = "native", feature = "wasm")))]
    {
        crypto_slh_dsa::sign_slh_dsa_sha2_128s(secret_key, message)
    }

    #[cfg(not(all(feature = "slh-dsa", any(feature = "native", feature = "wasm"))))]
    {
        let _ = (secret_key, message);
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

fn verify_slh_dsa_sha2_128s(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), OperationError> {
    #[cfg(all(feature = "slh-dsa", any(feature = "native", feature = "wasm")))]
    {
        crypto_slh_dsa::verify_slh_dsa_sha2_128s(public_key, message, signature)
    }

    #[cfg(not(all(feature = "slh-dsa", any(feature = "native", feature = "wasm"))))]
    {
        let _ = (public_key, message, signature);
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

fn signature_key_pair((public_key, secret_key): (Vec<u8>, Zeroizing<Vec<u8>>)) -> SignatureKeyPair {
    SignatureKeyPair {
        public_key,
        secret_key,
    }
}
