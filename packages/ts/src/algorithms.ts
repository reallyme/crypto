// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

export const REALLYME_SIGNATURE_ALGORITHMS = [
  "Ed25519",
  "ECDSA-P256-SHA256",
  "ECDSA-P384-SHA384",
  "ECDSA-P521-SHA512",
  "ECDSA-secp256k1-SHA256",
  "BIP340-Schnorr-secp256k1-SHA256",
  "RSA-PKCS1v15-SHA1",
  "RSA-PKCS1v15-SHA256",
  "RSA-PKCS1v15-SHA384",
  "RSA-PKCS1v15-SHA512",
  "RSA-PSS-SHA1-MGF1-SHA1",
  "RSA-PSS-SHA256-MGF1-SHA256",
  "RSA-PSS-SHA384-MGF1-SHA384",
  "RSA-PSS-SHA512-MGF1-SHA512",
  "ML-DSA-44",
  "ML-DSA-65",
  "ML-DSA-87",
  "SLH-DSA-SHA2-128s",
] as const;

export type ReallyMeSignatureAlgorithm =
  (typeof REALLYME_SIGNATURE_ALGORITHMS)[number];

export const REALLYME_HASH_ALGORITHMS = [
  "SHA2-256",
  "SHA2-384",
  "SHA2-512",
  "SHA3-224",
  "SHA3-256",
  "SHA3-384",
  "SHA3-512",
] as const;

export type ReallyMeHashAlgorithm = (typeof REALLYME_HASH_ALGORITHMS)[number];

export const REALLYME_AEAD_ALGORITHMS = [
  "AES-256-GCM",
  "AES-256-GCM-SIV",
  "ChaCha20-Poly1305",
  "XChaCha20-Poly1305",
] as const;

export type ReallyMeAeadAlgorithm = (typeof REALLYME_AEAD_ALGORITHMS)[number];

export const REALLYME_KEM_ALGORITHMS = [
  "ML-KEM-512",
  "ML-KEM-768",
  "ML-KEM-1024",
  "X-Wing-768",
  "X-Wing-1024",
] as const;

export type ReallyMeKemAlgorithm = (typeof REALLYME_KEM_ALGORITHMS)[number];

export const REALLYME_KEY_AGREEMENT_ALGORITHMS = [
  "X25519",
  "P-256-ECDH",
] as const;

export type ReallyMeKeyAgreementAlgorithm =
  (typeof REALLYME_KEY_AGREEMENT_ALGORITHMS)[number];

export const REALLYME_MAC_ALGORITHMS = [
  "HMAC-SHA-256",
  "HMAC-SHA-512",
] as const;

export type ReallyMeMacAlgorithm = (typeof REALLYME_MAC_ALGORITHMS)[number];

export const REALLYME_KDF_ALGORITHMS = [
  "HKDF-SHA256",
  "Argon2id",
  "PBKDF2-HMAC-SHA-256",
  "PBKDF2-HMAC-SHA-512",
] as const;

export type ReallyMeKdfAlgorithm = (typeof REALLYME_KDF_ALGORITHMS)[number];

export const REALLYME_KEY_WRAP_ALGORITHMS = ["AES-256-KW"] as const;

export type ReallyMeKeyWrapAlgorithm =
  (typeof REALLYME_KEY_WRAP_ALGORITHMS)[number];

export const REALLYME_HPKE_SUITES = [
  "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
  "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305",
] as const;

export type ReallyMeHpkeSuite = (typeof REALLYME_HPKE_SUITES)[number];
