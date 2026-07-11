// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::traits::{AeadCipherAlgorithm, AeadParams, SignatureAlgorithm};
use crate::AlgorithmError;
use crypto_core::{AeadAlgorithm, Algorithm};

// --- Signature algorithm adapters ---
use crate::algorithms::ed25519::Ed25519Algo;
use crate::algorithms::ml_dsa_44::MlDsa44Algo;
use crate::algorithms::ml_dsa_65::MlDsa65Algo;
use crate::algorithms::ml_dsa_87::MlDsa87Algo;
use crate::algorithms::p256::P256Algo;
use crate::algorithms::p384::P384Algo;
use crate::algorithms::p521::P521Algo;
use crate::algorithms::secp256k1::Secp256k1Algo;

// --- Key agreement / KEM adapters ---
use crate::algorithms::ml_kem_1024::MlKem1024Algo;
use crate::algorithms::ml_kem_512::MlKem512Algo;
use crate::algorithms::ml_kem_768::MlKem768Algo;
use crate::algorithms::x25519::X25519Algo;
use crate::algorithms::x_wing::{XWing1024Algo, XWing768Algo};

// --- Symmetric adapters ---
use crate::algorithms::aes256_gcm::Aes256GcmAlgo;
use crate::algorithms::aes256_gcm_siv::Aes256GcmSivAlgo;
use crate::algorithms::chacha20_poly1305::{ChaCha20Poly1305Algo, XChaCha20Poly1305Algo};

//
// -----------------------------------------------------------------------------
// Keypair generation (ALL ALGORITHMS)
// -----------------------------------------------------------------------------

/// Generate a raw keypair for the given algorithm.
///
/// This is supported for:
/// - signature algorithms
/// - key agreement algorithms
/// - KEM algorithms
///
/// Returns (public_key, secret_key); the secret half zeroizes on drop.
pub fn generate_keypair(alg: Algorithm) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
    match alg {
        Algorithm::Ed25519 => Ed25519Algo::generate_keypair(),
        Algorithm::P256 => P256Algo::generate_keypair(),
        Algorithm::P384 => P384Algo::generate_keypair(),
        Algorithm::P521 => P521Algo::generate_keypair(),
        Algorithm::Secp256k1 => Secp256k1Algo::generate_keypair(),
        Algorithm::MlDsa44 => MlDsa44Algo::generate_keypair(),
        Algorithm::MlDsa65 => MlDsa65Algo::generate_keypair(),
        Algorithm::MlDsa87 => MlDsa87Algo::generate_keypair(),

        Algorithm::X25519 => X25519Algo::generate_keypair(),
        Algorithm::MlKem512 => MlKem512Algo::generate_keypair(),
        Algorithm::MlKem768 => MlKem768Algo::generate_keypair(),
        Algorithm::MlKem1024 => MlKem1024Algo::generate_keypair(),
        Algorithm::XWing768 => XWing768Algo::generate_keypair(),
        Algorithm::XWing1024 => XWing1024Algo::generate_keypair(),
    }
}

//
// -----------------------------------------------------------------------------
// Signature algorithms ONLY
// -----------------------------------------------------------------------------

/// Sign `msg` with `secret` under the selected signature algorithm,
/// returning the detached signature bytes.
///
/// # Examples
///
/// ```
/// use crypto_core::Algorithm;
/// use crypto_dispatch::{generate_keypair, sign, verify};
///
/// # fn main() -> Result<(), crypto_dispatch::AlgorithmError> {
/// let (public, secret) = generate_keypair(Algorithm::Ed25519)?;
/// let signature = sign(Algorithm::Ed25519, &secret, b"message")?;
/// verify(Algorithm::Ed25519, &public, b"message", &signature)?;
/// # Ok(())
/// # }
/// ```
pub fn sign(alg: Algorithm, secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    match alg {
        Algorithm::Ed25519 => Ed25519Algo::sign(secret, msg),
        Algorithm::P256 => P256Algo::sign(secret, msg),
        Algorithm::P384 => P384Algo::sign(secret, msg),
        Algorithm::P521 => P521Algo::sign(secret, msg),
        Algorithm::Secp256k1 => Secp256k1Algo::sign(secret, msg),
        Algorithm::MlDsa44 => MlDsa44Algo::sign(secret, msg),
        Algorithm::MlDsa65 => MlDsa65Algo::sign(secret, msg),
        Algorithm::MlDsa87 => MlDsa87Algo::sign(secret, msg),
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}

/// Verify a detached signature.
///
/// Fails closed: a signature that does not verify is an
/// [`AlgorithmError::SignatureInvalid`] error, never a boolean, so a
/// forgotten result check cannot be mistaken for success.
///
/// # Examples
///
/// ```
/// use crypto_core::Algorithm;
/// use crypto_dispatch::{generate_keypair, sign, verify};
///
/// # fn main() -> Result<(), crypto_dispatch::AlgorithmError> {
/// let (public, secret) = generate_keypair(Algorithm::Ed25519)?;
/// let signature = sign(Algorithm::Ed25519, &secret, b"message")?;
///
/// // The signed message verifies.
/// verify(Algorithm::Ed25519, &public, b"message", &signature)?;
///
/// // A different message returns Err, never `Ok(false)`.
/// assert!(verify(Algorithm::Ed25519, &public, b"tampered", &signature).is_err());
/// # Ok(())
/// # }
/// ```
pub fn verify(alg: Algorithm, public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), AlgorithmError> {
    match alg {
        Algorithm::Ed25519 => Ed25519Algo::verify(public, msg, sig),
        Algorithm::P256 => P256Algo::verify(public, msg, sig),
        Algorithm::P384 => P384Algo::verify(public, msg, sig),
        Algorithm::P521 => P521Algo::verify(public, msg, sig),
        Algorithm::Secp256k1 => Secp256k1Algo::verify(public, msg, sig),
        Algorithm::MlDsa44 => MlDsa44Algo::verify(public, msg, sig),
        Algorithm::MlDsa65 => MlDsa65Algo::verify(public, msg, sig),
        Algorithm::MlDsa87 => MlDsa87Algo::verify(public, msg, sig),
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}

//
// -----------------------------------------------------------------------------
// ECDH / DH key agreement
// -----------------------------------------------------------------------------

/// Derive a Diffie–Hellman shared secret. The returned secret zeroizes on
/// drop.
pub fn derive_shared_secret(
    alg: Algorithm,
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
    match alg {
        Algorithm::P256 => P256Algo::derive_shared_secret(secret_key, public_key),
        Algorithm::X25519 => X25519Algo::derive_shared_secret(secret_key, public_key),
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}

//
// -----------------------------------------------------------------------------
// POST-QUANTUM KEM
// -----------------------------------------------------------------------------

/// Returns (shared_secret, ciphertext); the shared secret zeroizes on drop.
pub fn kem_encapsulate(
    alg: Algorithm,
    public_key: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), AlgorithmError> {
    match alg {
        Algorithm::MlKem512 => MlKem512Algo::encapsulate(public_key),
        Algorithm::MlKem768 => MlKem768Algo::encapsulate(public_key),
        Algorithm::MlKem1024 => MlKem1024Algo::encapsulate(public_key),
        Algorithm::XWing768 => XWing768Algo::encapsulate(public_key),
        Algorithm::XWing1024 => XWing1024Algo::encapsulate(public_key),
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}

/// Decapsulate a KEM ciphertext. The returned shared secret zeroizes on drop.
pub fn kem_decapsulate(
    alg: Algorithm,
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
    match alg {
        Algorithm::MlKem512 => MlKem512Algo::decapsulate(ciphertext, secret_key),
        Algorithm::MlKem768 => MlKem768Algo::decapsulate(ciphertext, secret_key),
        Algorithm::MlKem1024 => MlKem1024Algo::decapsulate(ciphertext, secret_key),
        Algorithm::XWing768 => XWing768Algo::decapsulate(ciphertext, secret_key),
        Algorithm::XWing1024 => XWing1024Algo::decapsulate(ciphertext, secret_key),
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}

//
// -----------------------------------------------------------------------------
// Symmetric AEAD
// -----------------------------------------------------------------------------

/// Encrypt `plaintext` with the selected AEAD. Returns
/// `ciphertext || tag`.
///
/// # Examples
///
/// ```
/// use crypto_core::AeadAlgorithm;
/// use crypto_dispatch::{aead_decrypt, aead_encrypt, AeadParams};
///
/// # fn main() -> Result<(), crypto_dispatch::AlgorithmError> {
/// let key = [0x42u8; 32];
/// let nonce = [0x24u8; 12];
/// let params = AeadParams { key: &key, nonce: &nonce, aad: b"context" };
///
/// let sealed = aead_encrypt(AeadAlgorithm::Aes256Gcm, &params, b"plaintext")?;
/// let opened = aead_decrypt(AeadAlgorithm::Aes256Gcm, &params, &sealed)?;
/// assert_eq!(opened.as_slice(), b"plaintext");
/// # Ok(())
/// # }
/// ```
pub fn aead_encrypt(
    alg: AeadAlgorithm,
    params: &AeadParams<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, AlgorithmError> {
    match alg {
        AeadAlgorithm::Aes256Gcm => Aes256GcmAlgo::encrypt(params, plaintext),
        AeadAlgorithm::Aes256GcmSiv => Aes256GcmSivAlgo::encrypt(params, plaintext),
        AeadAlgorithm::ChaCha20Poly1305 => ChaCha20Poly1305Algo::encrypt(params, plaintext),
        AeadAlgorithm::XChaCha20Poly1305 => XChaCha20Poly1305Algo::encrypt(params, plaintext),
    }
}

/// Decrypt and authenticate `ciphertext || tag` with the selected AEAD.
/// The returned plaintext is zeroized on drop.
///
/// Fails closed: a tampered ciphertext, tag, nonce, or AAD returns an error
/// instead of any plaintext.
///
/// # Examples
///
/// ```
/// use crypto_core::AeadAlgorithm;
/// use crypto_dispatch::{aead_decrypt, aead_encrypt, AeadParams};
///
/// # fn main() -> Result<(), crypto_dispatch::AlgorithmError> {
/// let key = [0x42u8; 32];
/// let nonce = [0x24u8; 12];
/// let params = AeadParams { key: &key, nonce: &nonce, aad: b"context" };
///
/// let sealed = aead_encrypt(AeadAlgorithm::Aes256GcmSiv, &params, b"plaintext")?;
/// let opened = aead_decrypt(AeadAlgorithm::Aes256GcmSiv, &params, &sealed)?;
/// assert_eq!(opened.as_slice(), b"plaintext");
/// # Ok(())
/// # }
/// ```
pub fn aead_decrypt(
    alg: AeadAlgorithm,
    params: &AeadParams<'_>,
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
    match alg {
        AeadAlgorithm::Aes256Gcm => Aes256GcmAlgo::decrypt(params, ciphertext_with_tag),
        AeadAlgorithm::Aes256GcmSiv => Aes256GcmSivAlgo::decrypt(params, ciphertext_with_tag),
        AeadAlgorithm::ChaCha20Poly1305 => {
            ChaCha20Poly1305Algo::decrypt(params, ciphertext_with_tag)
        }
        AeadAlgorithm::XChaCha20Poly1305 => {
            XChaCha20Poly1305Algo::decrypt(params, ciphertext_with_tag)
        }
    }
}
