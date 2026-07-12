// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Signature algorithm identifiers exposed by the package facade.
public enum ReallyMeSignatureAlgorithm: String, CaseIterable, Sendable {
    case ed25519 = "Ed25519"
    case ecdsaP256Sha256 = "ECDSA-P256-SHA256"
    case ecdsaP384Sha384 = "ECDSA-P384-SHA384"
    case ecdsaP521Sha512 = "ECDSA-P521-SHA512"
    case ecdsaSecp256k1Sha256 = "ECDSA-secp256k1-SHA256"
    case bip340SchnorrSecp256k1Sha256 = "BIP340-Schnorr-secp256k1-SHA256"
    case rsaPkcs1v15Sha1 = "RSA-PKCS1v15-SHA1"
    case rsaPkcs1v15Sha256 = "RSA-PKCS1v15-SHA256"
    case rsaPkcs1v15Sha384 = "RSA-PKCS1v15-SHA384"
    case rsaPkcs1v15Sha512 = "RSA-PKCS1v15-SHA512"
    case rsaPssSha1Mgf1Sha1 = "RSA-PSS-SHA1-MGF1-SHA1"
    case rsaPssSha256Mgf1Sha256 = "RSA-PSS-SHA256-MGF1-SHA256"
    case rsaPssSha384Mgf1Sha384 = "RSA-PSS-SHA384-MGF1-SHA384"
    case rsaPssSha512Mgf1Sha512 = "RSA-PSS-SHA512-MGF1-SHA512"
    case mlDsa44 = "ML-DSA-44"
    case mlDsa65 = "ML-DSA-65"
    case mlDsa87 = "ML-DSA-87"
    case slhDsaSha2_128s = "SLH-DSA-SHA2-128s"
}

/// Hash algorithm identifiers exposed by the package facade.
public enum ReallyMeHashAlgorithm: String, CaseIterable, Sendable {
    case sha2_256 = "SHA2-256"
    case sha2_384 = "SHA2-384"
    case sha2_512 = "SHA2-512"
    case sha3_224 = "SHA3-224"
    case sha3_256 = "SHA3-256"
    case sha3_384 = "SHA3-384"
    case sha3_512 = "SHA3-512"
}

/// AEAD algorithm identifiers reserved by the package facade.
public enum ReallyMeAeadAlgorithm: String, CaseIterable, Sendable {
    case aes128Gcm = "AES-128-GCM"
    case aes192Gcm = "AES-192-GCM"
    case aes256Gcm = "AES-256-GCM"
    case aes256GcmSiv = "AES-256-GCM-SIV"
    case chacha20Poly1305 = "ChaCha20-Poly1305"
    case xchacha20Poly1305 = "XChaCha20-Poly1305"
}

/// KEM algorithm identifiers reserved by the package facade.
public enum ReallyMeKemAlgorithm: String, CaseIterable, Sendable {
    case mlKem512 = "ML-KEM-512"
    case mlKem768 = "ML-KEM-768"
    case mlKem1024 = "ML-KEM-1024"
    case xWing768 = "X-Wing-768"
    case xWing1024 = "X-Wing-1024"
}

/// Direct key-agreement identifiers reserved by the package facade.
public enum ReallyMeKeyAgreementAlgorithm: String, CaseIterable, Sendable {
    case x25519 = "X25519"
    case p256Ecdh = "P-256-ECDH"
    case p384Ecdh = "P-384-ECDH"
    case p521Ecdh = "P-521-ECDH"
}

/// MAC algorithm identifiers reserved by the package facade.
public enum ReallyMeMacAlgorithm: String, CaseIterable, Sendable {
    case hmacSha256 = "HMAC-SHA-256"
    case hmacSha512 = "HMAC-SHA-512"
}

/// KDF identifiers reserved by the package facade.
public enum ReallyMeKdfAlgorithm: String, CaseIterable, Sendable {
    case hkdfSha256 = "HKDF-SHA256"
    case argon2id = "Argon2id"
    case pbkdf2HmacSha256 = "PBKDF2-HMAC-SHA-256"
    case pbkdf2HmacSha512 = "PBKDF2-HMAC-SHA-512"
    case jwaConcatKdfSha256 = "JWA-CONCAT-KDF-SHA256"
}

/// Key-wrap identifiers reserved by the package facade.
public enum ReallyMeKeyWrapAlgorithm: String, CaseIterable, Sendable {
    case aes256Kw = "AES-256-KW"
}

/// HPKE ciphersuite identifiers reserved by the package facade.
public enum ReallyMeHpkeSuite: String, CaseIterable, Sendable {
    case dhkemP256HkdfSha256HkdfSha256Aes256Gcm =
        "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM"
    case dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305 =
        "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305"
}
