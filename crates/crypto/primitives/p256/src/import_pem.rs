// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use codec_pem::{decode_pem, PemDecodePolicy, PemLabel};
use crypto_core::CryptoError;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use p256::{PublicKey, SecretKey};
use zeroize::{Zeroize, Zeroizing};

const P256_SECRET_KEY_LEN: usize = 32;
const P256_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
const P256_MAX_KEY_DER_LEN: usize = 4096;
const P256_MAX_KEY_PEM_LEN: usize = 8192;

/// Import a P-256 private scalar from PKCS#8 DER.
pub fn private_key_from_pkcs8_der(der: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let secret_key = SecretKey::from_pkcs8_der(der).map_err(|_| CryptoError::InvalidKey)?;
    secret_key_to_scalar(secret_key)
}

/// Import a P-256 private scalar from SEC1 ECPrivateKey DER.
pub fn private_key_from_sec1_der(der: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let secret_key = SecretKey::from_sec1_der(der).map_err(|_| CryptoError::InvalidKey)?;
    secret_key_to_scalar(secret_key)
}

/// Import a compressed P-256 SEC1 public key from SPKI DER.
pub fn public_key_from_spki_der(der: &[u8]) -> Result<[u8; 33], CryptoError> {
    let public_key = PublicKey::from_public_key_der(der).map_err(|_| CryptoError::InvalidKey)?;
    public_key_to_compressed(public_key)
}

/// Import a P-256 private scalar from a PKCS#8 `PRIVATE KEY` PEM document.
pub fn private_key_from_pkcs8_pem(pem: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let document = decode_pem(pem, pem_policy(&[PemLabel::PrivateKey]))
        .map_err(|_| CryptoError::InvalidKey)?;
    private_key_from_pkcs8_der(document.der.as_slice())
}

/// Import a P-256 private scalar from a SEC1 `EC PRIVATE KEY` PEM document.
pub fn private_key_from_sec1_pem(pem: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let document = decode_pem(pem, pem_policy(&[PemLabel::EcPrivateKey]))
        .map_err(|_| CryptoError::InvalidKey)?;
    private_key_from_sec1_der(document.der.as_slice())
}

/// Import a P-256 private scalar from either PKCS#8 or SEC1 PEM.
pub fn private_key_from_pem(pem: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let document = decode_pem(
        pem,
        pem_policy(&[PemLabel::PrivateKey, PemLabel::EcPrivateKey]),
    )
    .map_err(|_| CryptoError::InvalidKey)?;

    match document.label {
        PemLabel::PrivateKey => private_key_from_pkcs8_der(document.der.as_slice()),
        PemLabel::EcPrivateKey => private_key_from_sec1_der(document.der.as_slice()),
        PemLabel::PublicKey => Err(CryptoError::InvalidKey),
    }
}

/// Import a compressed P-256 SEC1 public key from a SPKI `PUBLIC KEY` PEM document.
pub fn public_key_from_spki_pem(pem: &str) -> Result<[u8; 33], CryptoError> {
    let document =
        decode_pem(pem, pem_policy(&[PemLabel::PublicKey])).map_err(|_| CryptoError::InvalidKey)?;
    public_key_from_spki_der(document.der.as_slice())
}

/// Derive the compressed SEC1 P-256 public key for a private scalar.
pub fn compressed_public_key_from_private_key(
    secret_key: &[u8; 32],
) -> Result<[u8; 33], CryptoError> {
    let secret = SecretKey::from_slice(secret_key).map_err(|_| CryptoError::InvalidKey)?;
    public_key_to_compressed(secret.public_key())
}

fn pem_policy(allowed_labels: &[PemLabel]) -> PemDecodePolicy<'_> {
    PemDecodePolicy {
        allowed_labels,
        max_input_len: P256_MAX_KEY_PEM_LEN,
        max_der_len: P256_MAX_KEY_DER_LEN,
    }
}

fn secret_key_to_scalar(secret_key: SecretKey) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut bytes = secret_key.to_bytes();
    if bytes.len() != P256_SECRET_KEY_LEN {
        bytes.zeroize();
        return Err(CryptoError::InvalidKey);
    }

    let mut scalar = Zeroizing::new([0u8; P256_SECRET_KEY_LEN]);
    scalar.copy_from_slice(bytes.as_slice());
    bytes.zeroize();
    Ok(scalar)
}

fn public_key_to_compressed(public_key: PublicKey) -> Result<[u8; 33], CryptoError> {
    let encoded = public_key.to_sec1_point(true);
    if encoded.as_bytes().len() != P256_PUBLIC_KEY_COMPRESSED_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let mut compressed = [0u8; P256_PUBLIC_KEY_COMPRESSED_LEN];
    compressed.copy_from_slice(encoded.as_bytes());
    Ok(compressed)
}
