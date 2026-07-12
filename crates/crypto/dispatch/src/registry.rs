// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

#[cfg(any(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305"
))]
use crate::traits::AeadCipherAlgorithm;
use crate::traits::AeadParams;
#[cfg(any(
    feature = "ed25519",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "secp256k1",
    feature = "ml-dsa-44",
    feature = "ml-dsa-65",
    feature = "ml-dsa-87"
))]
use crate::traits::SignatureAlgorithm;
use crate::AlgorithmError;
use crypto_core::{AeadAlgorithm, Algorithm};

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
        Algorithm::Ed25519 => {
            #[cfg(feature = "ed25519")]
            {
                crate::algorithms::ed25519::Ed25519Algo::generate_keypair()
            }
            #[cfg(not(feature = "ed25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                crate::algorithms::p256::P256Algo::generate_keypair()
            }
            #[cfg(not(feature = "p256"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                crate::algorithms::p384::P384Algo::generate_keypair()
            }
            #[cfg(not(feature = "p384"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                crate::algorithms::p521::P521Algo::generate_keypair()
            }
            #[cfg(not(feature = "p521"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "secp256k1")]
            {
                crate::algorithms::secp256k1::Secp256k1Algo::generate_keypair()
            }
            #[cfg(not(feature = "secp256k1"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa44 => {
            #[cfg(feature = "ml-dsa-44")]
            {
                crate::algorithms::ml_dsa_44::MlDsa44Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-dsa-44"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa65 => {
            #[cfg(feature = "ml-dsa-65")]
            {
                crate::algorithms::ml_dsa_65::MlDsa65Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-dsa-65"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa87 => {
            #[cfg(feature = "ml-dsa-87")]
            {
                crate::algorithms::ml_dsa_87::MlDsa87Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-dsa-87"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::X25519 => {
            #[cfg(feature = "x25519")]
            {
                crate::algorithms::x25519::X25519Algo::generate_keypair()
            }
            #[cfg(not(feature = "x25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                crate::algorithms::ml_kem_512::MlKem512Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                crate::algorithms::ml_kem_768::MlKem768Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                crate::algorithms::ml_kem_1024::MlKem1024Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::XWing768 => {
            #[cfg(feature = "x-wing")]
            {
                crate::algorithms::x_wing::XWing768Algo::generate_keypair()
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::XWing1024 => {
            #[cfg(feature = "x-wing")]
            {
                crate::algorithms::x_wing::XWing1024Algo::generate_keypair()
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
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
    #[cfg(not(any(
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "secp256k1",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87"
    )))]
    let _ = (secret, msg);

    match alg {
        Algorithm::Ed25519 => {
            #[cfg(feature = "ed25519")]
            {
                crate::algorithms::ed25519::Ed25519Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "ed25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                crate::algorithms::p256::P256Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "p256"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                crate::algorithms::p384::P384Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "p384"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                crate::algorithms::p521::P521Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "p521"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "secp256k1")]
            {
                crate::algorithms::secp256k1::Secp256k1Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "secp256k1"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa44 => {
            #[cfg(feature = "ml-dsa-44")]
            {
                crate::algorithms::ml_dsa_44::MlDsa44Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "ml-dsa-44"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa65 => {
            #[cfg(feature = "ml-dsa-65")]
            {
                crate::algorithms::ml_dsa_65::MlDsa65Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "ml-dsa-65"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa87 => {
            #[cfg(feature = "ml-dsa-87")]
            {
                crate::algorithms::ml_dsa_87::MlDsa87Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "ml-dsa-87"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
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
    #[cfg(not(any(
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "secp256k1",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87"
    )))]
    let _ = (public, msg, sig);

    match alg {
        Algorithm::Ed25519 => {
            #[cfg(feature = "ed25519")]
            {
                crate::algorithms::ed25519::Ed25519Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "ed25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                crate::algorithms::p256::P256Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "p256"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                crate::algorithms::p384::P384Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "p384"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                crate::algorithms::p521::P521Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "p521"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "secp256k1")]
            {
                crate::algorithms::secp256k1::Secp256k1Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "secp256k1"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa44 => {
            #[cfg(feature = "ml-dsa-44")]
            {
                crate::algorithms::ml_dsa_44::MlDsa44Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "ml-dsa-44"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa65 => {
            #[cfg(feature = "ml-dsa-65")]
            {
                crate::algorithms::ml_dsa_65::MlDsa65Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "ml-dsa-65"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa87 => {
            #[cfg(feature = "ml-dsa-87")]
            {
                crate::algorithms::ml_dsa_87::MlDsa87Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "ml-dsa-87"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
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
    #[cfg(not(any(
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "x25519"
    )))]
    let _ = (secret_key, public_key);

    match alg {
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                crate::algorithms::p256::P256Algo::derive_shared_secret(secret_key, public_key)
            }
            #[cfg(not(feature = "p256"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                crate::algorithms::p384::P384Algo::derive_shared_secret(secret_key, public_key)
            }
            #[cfg(not(feature = "p384"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                crate::algorithms::p521::P521Algo::derive_shared_secret(secret_key, public_key)
            }
            #[cfg(not(feature = "p521"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::X25519 => {
            #[cfg(feature = "x25519")]
            {
                crate::algorithms::x25519::X25519Algo::derive_shared_secret(secret_key, public_key)
            }
            #[cfg(not(feature = "x25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
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
    #[cfg(not(any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )))]
    let _ = public_key;

    match alg {
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                crate::algorithms::ml_kem_512::MlKem512Algo::encapsulate(public_key)
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                crate::algorithms::ml_kem_768::MlKem768Algo::encapsulate(public_key)
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                crate::algorithms::ml_kem_1024::MlKem1024Algo::encapsulate(public_key)
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::XWing768 => {
            #[cfg(feature = "x-wing")]
            {
                crate::algorithms::x_wing::XWing768Algo::encapsulate(public_key)
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::XWing1024 => {
            #[cfg(feature = "x-wing")]
            {
                crate::algorithms::x_wing::XWing1024Algo::encapsulate(public_key)
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}

/// Decapsulate a KEM ciphertext. The returned shared secret zeroizes on drop.
pub fn kem_decapsulate(
    alg: Algorithm,
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
    #[cfg(not(any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )))]
    let _ = (ciphertext, secret_key);

    match alg {
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                crate::algorithms::ml_kem_512::MlKem512Algo::decapsulate(ciphertext, secret_key)
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                crate::algorithms::ml_kem_768::MlKem768Algo::decapsulate(ciphertext, secret_key)
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                crate::algorithms::ml_kem_1024::MlKem1024Algo::decapsulate(ciphertext, secret_key)
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::XWing768 => {
            #[cfg(feature = "x-wing")]
            {
                crate::algorithms::x_wing::XWing768Algo::decapsulate(ciphertext, secret_key)
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::XWing1024 => {
            #[cfg(feature = "x-wing")]
            {
                crate::algorithms::x_wing::XWing1024Algo::decapsulate(ciphertext, secret_key)
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
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
    #[cfg(not(any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    )))]
    let _ = (params, plaintext);

    match alg {
        AeadAlgorithm::Aes128Gcm => {
            #[cfg(feature = "aes")]
            {
                crate::algorithms::aes256_gcm::Aes128GcmAlgo::encrypt(params, plaintext)
            }
            #[cfg(not(feature = "aes"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
        AeadAlgorithm::Aes192Gcm => {
            #[cfg(feature = "aes")]
            {
                crate::algorithms::aes256_gcm::Aes192GcmAlgo::encrypt(params, plaintext)
            }
            #[cfg(not(feature = "aes"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
        AeadAlgorithm::Aes256Gcm => {
            #[cfg(feature = "aes")]
            {
                crate::algorithms::aes256_gcm::Aes256GcmAlgo::encrypt(params, plaintext)
            }
            #[cfg(not(feature = "aes"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
        AeadAlgorithm::Aes256GcmSiv => {
            #[cfg(feature = "aes-gcm-siv")]
            {
                crate::algorithms::aes256_gcm_siv::Aes256GcmSivAlgo::encrypt(params, plaintext)
            }
            #[cfg(not(feature = "aes-gcm-siv"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            #[cfg(feature = "chacha20-poly1305")]
            {
                crate::algorithms::chacha20_poly1305::ChaCha20Poly1305Algo::encrypt(
                    params, plaintext,
                )
            }
            #[cfg(not(feature = "chacha20-poly1305"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
        AeadAlgorithm::XChaCha20Poly1305 => {
            #[cfg(feature = "chacha20-poly1305")]
            {
                crate::algorithms::chacha20_poly1305::XChaCha20Poly1305Algo::encrypt(
                    params, plaintext,
                )
            }
            #[cfg(not(feature = "chacha20-poly1305"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
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
    #[cfg(not(any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    )))]
    let _ = (params, ciphertext_with_tag);

    match alg {
        AeadAlgorithm::Aes128Gcm => {
            #[cfg(feature = "aes")]
            {
                crate::algorithms::aes256_gcm::Aes128GcmAlgo::decrypt(params, ciphertext_with_tag)
            }
            #[cfg(not(feature = "aes"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
        AeadAlgorithm::Aes192Gcm => {
            #[cfg(feature = "aes")]
            {
                crate::algorithms::aes256_gcm::Aes192GcmAlgo::decrypt(params, ciphertext_with_tag)
            }
            #[cfg(not(feature = "aes"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
        AeadAlgorithm::Aes256Gcm => {
            #[cfg(feature = "aes")]
            {
                crate::algorithms::aes256_gcm::Aes256GcmAlgo::decrypt(params, ciphertext_with_tag)
            }
            #[cfg(not(feature = "aes"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
        AeadAlgorithm::Aes256GcmSiv => {
            #[cfg(feature = "aes-gcm-siv")]
            {
                crate::algorithms::aes256_gcm_siv::Aes256GcmSivAlgo::decrypt(
                    params,
                    ciphertext_with_tag,
                )
            }
            #[cfg(not(feature = "aes-gcm-siv"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            #[cfg(feature = "chacha20-poly1305")]
            {
                crate::algorithms::chacha20_poly1305::ChaCha20Poly1305Algo::decrypt(
                    params,
                    ciphertext_with_tag,
                )
            }
            #[cfg(not(feature = "chacha20-poly1305"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
        AeadAlgorithm::XChaCha20Poly1305 => {
            #[cfg(feature = "chacha20-poly1305")]
            {
                crate::algorithms::chacha20_poly1305::XChaCha20Poly1305Algo::decrypt(
                    params,
                    ciphertext_with_tag,
                )
            }
            #[cfg(not(feature = "chacha20-poly1305"))]
            {
                Err(AlgorithmError::UnsupportedAeadAlgorithm(alg))
            }
        }
    }
}
