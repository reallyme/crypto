// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::identifiers::HpkeSuite;

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

/// HPKE PSK-mode encryption request.
pub struct HpkePskSealRequest<'a> {
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
    /// High-entropy pre-shared key.
    pub psk: &'a [u8],
    /// Application identifier for the pre-shared key.
    pub psk_id: &'a [u8],
}

/// HPKE PSK-mode decryption request.
pub struct HpkePskOpenRequest<'a> {
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
    /// High-entropy pre-shared key.
    pub psk: &'a [u8],
    /// Application identifier for the pre-shared key.
    pub psk_id: &'a [u8],
}

/// HPKE sender secret-export request.
pub struct HpkeSenderExportRequest<'a> {
    /// Ciphersuite to use, including export-only where appropriate.
    pub suite: HpkeSuite,
    /// Encoded recipient public key.
    pub recipient_public_key: &'a [u8],
    /// RFC 9180 `info` value.
    pub info: &'a [u8],
    /// Exporter context bound into the exported secret.
    pub exporter_context: &'a [u8],
    /// Requested output length.
    pub output_length: usize,
}

/// HPKE receiver secret-export request.
pub struct HpkeReceiverExportRequest<'a> {
    /// Ciphersuite to use, including export-only where appropriate.
    pub suite: HpkeSuite,
    /// Encapsulated key produced by sender setup.
    pub encapsulated_key: &'a [u8],
    /// Encoded recipient private key.
    pub recipient_private_key: &'a [u8],
    /// RFC 9180 `info` value.
    pub info: &'a [u8],
    /// Exporter context bound into the exported secret.
    pub exporter_context: &'a [u8],
    /// Requested output length.
    pub output_length: usize,
}

/// HPKE encryption result.
pub struct HpkeSealOutput {
    /// Encapsulated key to send with the ciphertext.
    pub encapsulated_key: Vec<u8>,
    /// Ciphertext with authentication tag.
    pub ciphertext: Vec<u8>,
}

/// HPKE decryption result.
pub struct HpkeOpenOutput {
    /// Decrypted plaintext. Message payloads can contain user data or secrets.
    pub plaintext: Zeroizing<Vec<u8>>,
}

/// HPKE sender export result.
pub struct HpkeSenderExportOutput {
    /// Encapsulated key required by the receiver setup.
    pub encapsulated_key: Vec<u8>,
    exporter_secret: Zeroizing<Vec<u8>>,
}

impl HpkeSenderExportOutput {
    #[cfg(feature = "native")]
    pub(crate) fn new(encapsulated_key: Vec<u8>, exporter_secret: Zeroizing<Vec<u8>>) -> Self {
        Self {
            encapsulated_key,
            exporter_secret,
        }
    }

    /// Borrows the zeroizing exporter output.
    pub fn exporter_secret(&self) -> &[u8] {
        self.exporter_secret.as_slice()
    }

    /// Transfers the exporter output into a zeroizing owner.
    pub fn into_exporter_secret(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(&mut *self.exporter_secret))
    }
}

/// HPKE receiver exporter output.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkeExporterSecret {
    bytes: Vec<u8>,
}

impl HpkeExporterSecret {
    #[cfg(feature = "native")]
    pub(crate) fn new(mut bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            bytes: core::mem::take(&mut *bytes),
        }
    }

    /// Borrows the exporter output.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// HPKE KEM keypair.
pub struct HpkeKeyPair {
    /// Encoded public key.
    pub public_key: Vec<u8>,
    private_key: HpkePrivateKeyBytes,
}

impl HpkeKeyPair {
    #[cfg(feature = "native")]
    pub(crate) fn new(public_key: Vec<u8>, private_key: HpkePrivateKeyBytes) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Borrows the zeroizing private key.
    pub fn private_key(&self) -> &[u8] {
        self.private_key.as_slice()
    }

    /// Transfers the private key into its zeroizing owner type.
    pub fn into_private_key(self) -> HpkePrivateKeyBytes {
        self.private_key
    }
}

/// HPKE deterministic encryption request for conformance vectors.
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

/// Typed zeroizing owner for an encoded HPKE private key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkePrivateKeyBytes {
    bytes: Vec<u8>,
}

impl HpkePrivateKeyBytes {
    /// Creates a new zeroizing private-key owner.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrows the private-key bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}
