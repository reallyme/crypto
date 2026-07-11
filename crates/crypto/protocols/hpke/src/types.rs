// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::constants::{
    HPKE_AEAD_AES_256_GCM, HPKE_AEAD_CHACHA20_POLY1305, HPKE_AEAD_TAG_LEN, HPKE_KDF_HKDF_SHA256,
    HPKE_KEM_DHKEM_P256_HKDF_SHA256, HPKE_KEM_DHKEM_X25519_HKDF_SHA256, HPKE_P256_PRIVATE_KEY_LEN,
    HPKE_P256_PUBLIC_KEY_LEN, HPKE_X25519_PRIVATE_KEY_LEN, HPKE_X25519_PUBLIC_KEY_LEN,
};

/// Supported HPKE Base-mode ciphersuites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeSuite {
    /// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
    P256Sha256Aes256Gcm,
    /// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
    X25519Sha256ChaCha20Poly1305,
}

impl HpkeSuite {
    /// HPKE KEM identifier.
    pub const fn kem_id(self) -> u16 {
        match self {
            Self::P256Sha256Aes256Gcm => HPKE_KEM_DHKEM_P256_HKDF_SHA256,
            Self::X25519Sha256ChaCha20Poly1305 => HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
        }
    }

    /// HPKE KDF identifier.
    pub const fn kdf_id(self) -> u16 {
        HPKE_KDF_HKDF_SHA256
    }

    /// HPKE AEAD identifier.
    pub const fn aead_id(self) -> u16 {
        match self {
            Self::P256Sha256Aes256Gcm => HPKE_AEAD_AES_256_GCM,
            Self::X25519Sha256ChaCha20Poly1305 => HPKE_AEAD_CHACHA20_POLY1305,
        }
    }

    /// Encoded public key and encapsulated key length for this suite.
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::P256Sha256Aes256Gcm => HPKE_P256_PUBLIC_KEY_LEN,
            Self::X25519Sha256ChaCha20Poly1305 => HPKE_X25519_PUBLIC_KEY_LEN,
        }
    }

    /// Encoded private key length for this suite.
    pub const fn private_key_len(self) -> usize {
        match self {
            Self::P256Sha256Aes256Gcm => HPKE_P256_PRIVATE_KEY_LEN,
            Self::X25519Sha256ChaCha20Poly1305 => HPKE_X25519_PRIVATE_KEY_LEN,
        }
    }

    /// AEAD tag length for this suite.
    pub const fn tag_len(self) -> usize {
        HPKE_AEAD_TAG_LEN
    }
}

/// HPKE Base-mode encryption request.
pub struct HpkeSealRequest<'a> {
    /// Ciphersuite to use.
    pub suite: HpkeSuite,
    /// Encoded recipient public key.
    pub recipient_public_key: &'a [u8],
    /// RFC 9180 `info` value.
    pub info: &'a [u8],
    /// Associated data authenticated with the ciphertext.
    pub aad: &'a [u8],
    /// Plaintext to encrypt.
    pub plaintext: &'a [u8],
}

/// HPKE Base-mode decryption request.
pub struct HpkeOpenRequest<'a> {
    /// Ciphersuite to use.
    pub suite: HpkeSuite,
    /// Encapsulated key produced by the sender.
    pub encapsulated_key: &'a [u8],
    /// Encoded recipient private key.
    pub recipient_private_key: &'a [u8],
    /// RFC 9180 `info` value.
    pub info: &'a [u8],
    /// Associated data authenticated with the ciphertext.
    pub aad: &'a [u8],
    /// Ciphertext with authentication tag.
    pub ciphertext: &'a [u8],
}

/// HPKE Base-mode encryption result.
pub struct HpkeSealOutput {
    /// Encapsulated key to send with the ciphertext.
    pub encapsulated_key: Vec<u8>,
    /// Ciphertext with authentication tag.
    pub ciphertext: Vec<u8>,
}

/// HPKE Base-mode decryption result.
pub struct HpkeOpenOutput {
    /// Decrypted plaintext. This zeroizes on drop because message payloads may
    /// contain user data or application secrets.
    pub plaintext: Zeroizing<Vec<u8>>,
}

/// HPKE Base-mode deterministic encryption request for conformance vectors.
#[cfg(feature = "test-vectors")]
pub struct HpkeDerandSealRequest<'a> {
    /// Ciphersuite to use.
    pub suite: HpkeSuite,
    /// Encoded recipient public key.
    pub recipient_public_key: &'a [u8],
    /// Suite-specific randomness consumed by the HPKE KEM.
    pub encapsulation_randomness: &'a [u8],
    /// RFC 9180 `info` value.
    pub info: &'a [u8],
    /// Associated data authenticated with the ciphertext.
    pub aad: &'a [u8],
    /// Plaintext to encrypt.
    pub plaintext: &'a [u8],
}

/// Secret key buffer used by package adapters that need a typed zeroizing
/// owner before calling into the protocol wrapper.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkePrivateKeyBytes {
    bytes: Vec<u8>,
}

impl HpkePrivateKeyBytes {
    /// Creates a new zeroizing private key owner.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrows the private key bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}
