// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// HPKE KEM identifier for DHKEM(P-256, HKDF-SHA256), RFC 9180 section 7.1.
pub const HPKE_KEM_DHKEM_P256_HKDF_SHA256: u16 = 0x0010;
/// HPKE KEM identifier for DHKEM(X25519, HKDF-SHA256), RFC 9180 section 7.1.
pub const HPKE_KEM_DHKEM_X25519_HKDF_SHA256: u16 = 0x0020;
/// HPKE KDF identifier for HKDF-SHA256, RFC 9180 section 7.2.
pub const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
/// HPKE AEAD identifier for AES-256-GCM, RFC 9180 section 7.3.
pub const HPKE_AEAD_AES_256_GCM: u16 = 0x0002;
/// HPKE AEAD identifier for ChaCha20-Poly1305, RFC 9180 section 7.3.
pub const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;

/// SEC1 uncompressed P-256 HPKE public key length in bytes.
pub const HPKE_P256_PUBLIC_KEY_LEN: usize = 65;
/// P-256 scalar private key length in bytes.
pub const HPKE_P256_PRIVATE_KEY_LEN: usize = 32;
/// X25519 HPKE public key length in bytes.
pub const HPKE_X25519_PUBLIC_KEY_LEN: usize = 32;
/// X25519 HPKE private key length in bytes.
pub const HPKE_X25519_PRIVATE_KEY_LEN: usize = 32;
/// Maximum encapsulated key length for the supported HPKE Base suites.
pub const HPKE_ENCAPSULATED_KEY_MAX_LEN: usize = HPKE_P256_PUBLIC_KEY_LEN;
/// AES-GCM and ChaCha20-Poly1305 authentication tag length in HPKE.
pub const HPKE_AEAD_TAG_LEN: usize = 16;
