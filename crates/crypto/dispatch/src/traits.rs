// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::AlgorithmError;
use crypto_core::{AeadAlgorithm, Algorithm, HashAlgorithm, MacAlgorithm};

/// Borrowed AEAD inputs. Key and nonce lengths are validated by the
/// selected algorithm's typed constructors at dispatch time, so a wrong
/// length fails closed with a typed error instead of being truncated or
/// padded.
pub struct AeadParams<'a> {
    /// Symmetric key bytes; length is validated by the selected algorithm.
    pub key: &'a [u8],
    /// Nonce bytes; length is validated by the selected algorithm.
    pub nonce: &'a [u8],
    /// Additional authenticated data bound to the ciphertext (may be empty).
    pub aad: &'a [u8],
}

/// Borrowed HMAC inputs. The selected algorithm validates key and tag lengths
/// before authenticating so callers cannot accidentally compare truncated tags.
pub struct MacParams<'a> {
    /// Symmetric key bytes; length is validated by the selected algorithm.
    pub key: &'a [u8],
}

/// Adapter contract for a detached-signature algorithm.
pub trait SignatureAlgorithm {
    /// The algorithm selector this adapter implements.
    const ALG: Algorithm;

    /// Generate a keypair, returning `(public_key, secret_key)`; the secret
    /// zeroizes on drop.
    fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError>;
    /// Sign `msg` with `secret`, returning the detached signature bytes.
    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, AlgorithmError>;
    /// Verify `sig` over `msg` against `public`; invalid signatures fail closed.
    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), AlgorithmError>;
}

/// Adapter contract for an AEAD cipher algorithm.
pub trait AeadCipherAlgorithm {
    /// The AEAD algorithm selector this adapter implements.
    const ALG: AeadAlgorithm;

    /// Encrypt `plaintext` under `params`, returning `ciphertext || tag`.
    fn encrypt(params: &AeadParams<'_>, plaintext: &[u8]) -> Result<Vec<u8>, AlgorithmError>;
    /// Decrypt and authenticate `ciphertext || tag`; fails closed on a
    /// tampered ciphertext or AAD. Returned plaintext zeroizes on drop.
    fn decrypt(
        params: &AeadParams<'_>,
        ciphertext_with_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AlgorithmError>;
}

/// Adapter contract for a cryptographic hash algorithm.
pub trait HashDigestAlgorithm {
    /// The hash algorithm selector this adapter implements.
    const ALG: HashAlgorithm;

    /// Compute the digest of `message`, returning the raw digest bytes.
    fn digest(message: &[u8]) -> Result<Vec<u8>, AlgorithmError>;
}

/// Adapter contract for a message authentication code algorithm.
pub trait MacAlgorithmAdapter {
    /// The MAC algorithm selector this adapter implements.
    const ALG: MacAlgorithm;

    /// Compute a MAC tag over `message`.
    fn authenticate(params: &MacParams<'_>, message: &[u8]) -> Result<Vec<u8>, AlgorithmError>;
    /// Verify `tag` over `message`; failures are returned as typed errors.
    fn verify(params: &MacParams<'_>, message: &[u8], tag: &[u8]) -> Result<(), AlgorithmError>;
}
