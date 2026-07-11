// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_return)]

use crate::AlgorithmError;
use codec_multikey::encode_multikey;
use crypto_core::Algorithm;

fn compress_p256_public_key(input: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    #[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
    {
        return crypto_p256::compress_p256(input)
            .map_err(|_| AlgorithmError::InvalidKey(Algorithm::P256));
    }

    #[cfg(all(feature = "wasm", target_arch = "wasm32"))]
    {
        return crypto_p256::compress_p256(input)
            .map_err(|_| AlgorithmError::InvalidKey(Algorithm::P256));
    }

    #[cfg(not(any(
        all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))),
        all(feature = "wasm", target_arch = "wasm32")
    )))]
    {
        let _ = input;
        Err(AlgorithmError::UnsupportedAlgorithm(Algorithm::P256))
    }
}

fn compress_p384_public_key(input: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    #[cfg(any(feature = "native", feature = "wasm"))]
    {
        return crypto_p384::compress_p384(input)
            .map_err(|_| AlgorithmError::InvalidKey(Algorithm::P384));
    }

    #[cfg(not(any(feature = "native", feature = "wasm")))]
    {
        let _ = input;
        Err(AlgorithmError::UnsupportedAlgorithm(Algorithm::P384))
    }
}

fn compress_p521_public_key(input: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    #[cfg(any(feature = "native", feature = "wasm"))]
    {
        return crypto_p521::compress_p521(input)
            .map_err(|_| AlgorithmError::InvalidKey(Algorithm::P521));
    }

    #[cfg(not(any(feature = "native", feature = "wasm")))]
    {
        let _ = input;
        Err(AlgorithmError::UnsupportedAlgorithm(Algorithm::P521))
    }
}

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
pub fn public_key_to_multikey(alg: Algorithm, public_key: &[u8]) -> Result<String, AlgorithmError> {
    let (codec, key_bytes) = match alg {
        Algorithm::Ed25519 => ("ed25519-pub", public_key.to_vec()),
        Algorithm::X25519 => ("x25519-pub", public_key.to_vec()),
        Algorithm::Secp256k1 => ("secp256k1-pub", public_key.to_vec()),
        Algorithm::P384 => (
            "p384-pub",
            canonicalize_sec1_public_key(
                alg,
                public_key,
                crypto_p384::P384_PUBLIC_KEY_COMPRESSED_LEN,
                crypto_p384::P384_PUBLIC_KEY_UNCOMPRESSED_LEN,
                crypto_p384::P384_PUBLIC_KEY_RAW_LEN,
                compress_p384_public_key,
            )?,
        ),
        Algorithm::P521 => (
            "p521-pub",
            canonicalize_sec1_public_key(
                alg,
                public_key,
                crypto_p521::P521_PUBLIC_KEY_COMPRESSED_LEN,
                crypto_p521::P521_PUBLIC_KEY_UNCOMPRESSED_LEN,
                crypto_p521::P521_PUBLIC_KEY_RAW_LEN,
                compress_p521_public_key,
            )?,
        ),
        Algorithm::MlDsa44 => ("mldsa-44-pub", public_key.to_vec()),
        Algorithm::MlDsa65 => ("mldsa-65-pub", public_key.to_vec()),
        Algorithm::MlDsa87 => ("mldsa-87-pub", public_key.to_vec()),
        Algorithm::MlKem512 => ("mlkem-512-pub", public_key.to_vec()),
        Algorithm::MlKem768 => ("mlkem-768-pub", public_key.to_vec()),
        Algorithm::MlKem1024 => ("mlkem-1024-pub", public_key.to_vec()),
        Algorithm::XWing768 | Algorithm::XWing1024 => {
            return Err(AlgorithmError::UnsupportedAlgorithm(alg));
        }

        // Canonicalization step: P-256 must be compressed
        Algorithm::P256 => {
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
    };

    encode_multikey(codec, &key_bytes).map_err(|_| AlgorithmError::InvalidKey(alg))
}
