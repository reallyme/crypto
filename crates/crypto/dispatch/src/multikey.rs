// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_return)]

use crate::AlgorithmError;
#[cfg(any(
    feature = "ed25519",
    feature = "x25519",
    feature = "secp256k1",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "ml-dsa-44",
    feature = "ml-dsa-65",
    feature = "ml-dsa-87",
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024"
))]
use codec_multikey::encode_multikey;
use crypto_core::Algorithm;

#[cfg(feature = "p256")]
fn compress_p256_public_key(input: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    #[cfg(all(
        feature = "p256",
        feature = "native",
        not(all(feature = "wasm", target_arch = "wasm32"))
    ))]
    {
        return crypto_p256::compress_p256(input)
            .map_err(|_| AlgorithmError::InvalidKey(Algorithm::P256));
    }

    #[cfg(all(feature = "p256", feature = "wasm", target_arch = "wasm32"))]
    {
        return crypto_p256::compress_p256(input)
            .map_err(|_| AlgorithmError::InvalidKey(Algorithm::P256));
    }

    #[cfg(not(any(
        all(
            feature = "p256",
            feature = "native",
            not(all(feature = "wasm", target_arch = "wasm32"))
        ),
        all(feature = "p256", feature = "wasm", target_arch = "wasm32")
    )))]
    {
        let _ = input;
        Err(AlgorithmError::UnsupportedAlgorithm(Algorithm::P256))
    }
}

#[cfg(feature = "p384")]
fn compress_p384_public_key(input: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    #[cfg(all(
        feature = "p384",
        feature = "native",
        not(all(feature = "wasm", target_arch = "wasm32"))
    ))]
    {
        return crypto_p384::compress_p384(input)
            .map_err(|_| AlgorithmError::InvalidKey(Algorithm::P384));
    }

    #[cfg(all(feature = "p384", feature = "wasm", target_arch = "wasm32"))]
    {
        return crypto_p384::compress_p384(input)
            .map_err(|_| AlgorithmError::InvalidKey(Algorithm::P384));
    }

    #[cfg(not(any(
        all(
            feature = "p384",
            feature = "native",
            not(all(feature = "wasm", target_arch = "wasm32"))
        ),
        all(feature = "p384", feature = "wasm", target_arch = "wasm32")
    )))]
    {
        let _ = input;
        Err(AlgorithmError::UnsupportedAlgorithm(Algorithm::P384))
    }
}

#[cfg(feature = "p521")]
fn compress_p521_public_key(input: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    #[cfg(all(
        feature = "p521",
        feature = "native",
        not(all(feature = "wasm", target_arch = "wasm32"))
    ))]
    {
        return crypto_p521::compress_p521(input)
            .map_err(|_| AlgorithmError::InvalidKey(Algorithm::P521));
    }

    #[cfg(all(feature = "p521", feature = "wasm", target_arch = "wasm32"))]
    {
        return crypto_p521::compress_p521(input)
            .map_err(|_| AlgorithmError::InvalidKey(Algorithm::P521));
    }

    #[cfg(not(any(
        all(
            feature = "p521",
            feature = "native",
            not(all(feature = "wasm", target_arch = "wasm32"))
        ),
        all(feature = "p521", feature = "wasm", target_arch = "wasm32")
    )))]
    {
        let _ = input;
        Err(AlgorithmError::UnsupportedAlgorithm(Algorithm::P521))
    }
}

#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
fn canonicalize_sec1_public_key(
    alg: Algorithm,
    public_key: &[u8],
    compressed_len: usize,
    uncompressed_len: usize,
    raw_len: usize,
    compress: fn(&[u8]) -> Result<Vec<u8>, AlgorithmError>,
) -> Result<Vec<u8>, AlgorithmError> {
    match public_key.len() {
        len if len == compressed_len => Ok(public_key.to_vec()),
        len if len == uncompressed_len => compress(public_key),
        len if len == raw_len => {
            let capacity = raw_len
                .checked_add(1)
                .ok_or(AlgorithmError::InvalidKey(alg))?;
            let mut sec1 = Vec::with_capacity(capacity);
            sec1.push(0x04);
            sec1.extend_from_slice(public_key);
            compress(&sec1)
        }
        _ => Err(AlgorithmError::InvalidKey(alg)),
    }
}

/// Multicodec/multikey-encode a public key, canonicalizing P-256 to its
/// compressed SEC1 form. Returns the `z`-prefixed multikey string.
#[cfg(not(any(
    feature = "ed25519",
    feature = "x25519",
    feature = "secp256k1",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "ml-dsa-44",
    feature = "ml-dsa-65",
    feature = "ml-dsa-87",
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024"
)))]
pub fn public_key_to_multikey(alg: Algorithm, public_key: &[u8]) -> Result<String, AlgorithmError> {
    let _ = public_key;
    Err(AlgorithmError::UnsupportedAlgorithm(alg))
}

/// Multicodec/multikey-encode a public key, canonicalizing P-256 to its
/// compressed SEC1 form. Returns the `z`-prefixed multikey string.
#[cfg(any(
    feature = "ed25519",
    feature = "x25519",
    feature = "secp256k1",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "ml-dsa-44",
    feature = "ml-dsa-65",
    feature = "ml-dsa-87",
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024"
))]
pub fn public_key_to_multikey(alg: Algorithm, public_key: &[u8]) -> Result<String, AlgorithmError> {
    let (codec, key_bytes) = match alg {
        Algorithm::Ed25519 => {
            #[cfg(feature = "ed25519")]
            {
                ("ed25519-pub", public_key.to_vec())
            }
            #[cfg(not(feature = "ed25519"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::X25519 => {
            #[cfg(feature = "x25519")]
            {
                ("x25519-pub", public_key.to_vec())
            }
            #[cfg(not(feature = "x25519"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "secp256k1")]
            {
                ("secp256k1-pub", public_key.to_vec())
            }
            #[cfg(not(feature = "secp256k1"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                (
                    "p384-pub",
                    canonicalize_sec1_public_key(
                        alg,
                        public_key,
                        crypto_p384::P384_PUBLIC_KEY_COMPRESSED_LEN,
                        crypto_p384::P384_PUBLIC_KEY_UNCOMPRESSED_LEN,
                        crypto_p384::P384_PUBLIC_KEY_RAW_LEN,
                        compress_p384_public_key,
                    )?,
                )
            }
            #[cfg(not(feature = "p384"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                (
                    "p521-pub",
                    canonicalize_sec1_public_key(
                        alg,
                        public_key,
                        crypto_p521::P521_PUBLIC_KEY_COMPRESSED_LEN,
                        crypto_p521::P521_PUBLIC_KEY_UNCOMPRESSED_LEN,
                        crypto_p521::P521_PUBLIC_KEY_RAW_LEN,
                        compress_p521_public_key,
                    )?,
                )
            }
            #[cfg(not(feature = "p521"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::MlDsa44 => {
            #[cfg(feature = "ml-dsa-44")]
            {
                ("mldsa-44-pub", public_key.to_vec())
            }
            #[cfg(not(feature = "ml-dsa-44"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::MlDsa65 => {
            #[cfg(feature = "ml-dsa-65")]
            {
                ("mldsa-65-pub", public_key.to_vec())
            }
            #[cfg(not(feature = "ml-dsa-65"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::MlDsa87 => {
            #[cfg(feature = "ml-dsa-87")]
            {
                ("mldsa-87-pub", public_key.to_vec())
            }
            #[cfg(not(feature = "ml-dsa-87"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                ("mlkem-512-pub", public_key.to_vec())
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                ("mlkem-768-pub", public_key.to_vec())
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                ("mlkem-1024-pub", public_key.to_vec())
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }
        }
        Algorithm::XWing768 | Algorithm::XWing1024 => {
            return Err(AlgorithmError::UnsupportedAlgorithm(alg));
        }

        // Canonicalization step: P-256 must be compressed
        Algorithm::P256 => {
            #[cfg(not(feature = "p256"))]
            {
                return Err(AlgorithmError::UnsupportedAlgorithm(alg));
            }

            #[cfg(feature = "p256")]
            {
                let compressed = canonicalize_sec1_public_key(
                    alg,
                    public_key,
                    33,
                    65,
                    64,
                    compress_p256_public_key,
                )?;

                ("p256-pub", compressed)
            }
        }
    };

    encode_multikey(codec, &key_bytes).map_err(|_| AlgorithmError::InvalidKey(alg))
}
