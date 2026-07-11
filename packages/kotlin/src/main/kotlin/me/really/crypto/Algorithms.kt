// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

public enum class ReallyMeSignatureAlgorithm(public val algorithmName: String) {
    ED25519("Ed25519"),
    ECDSA_P256_SHA256("ECDSA-P256-SHA256"),
    ECDSA_P384_SHA384("ECDSA-P384-SHA384"),
    ECDSA_P521_SHA512("ECDSA-P521-SHA512"),
    ECDSA_SECP256K1_SHA256("ECDSA-secp256k1-SHA256"),
    BIP340_SCHNORR_SECP256K1_SHA256("BIP340-Schnorr-secp256k1-SHA256"),
    RSA_PKCS1V15_SHA1("RSA-PKCS1v15-SHA1"),
    RSA_PKCS1V15_SHA256("RSA-PKCS1v15-SHA256"),
    RSA_PKCS1V15_SHA384("RSA-PKCS1v15-SHA384"),
    RSA_PKCS1V15_SHA512("RSA-PKCS1v15-SHA512"),
    RSA_PSS_SHA1_MGF1_SHA1("RSA-PSS-SHA1-MGF1-SHA1"),
    RSA_PSS_SHA256_MGF1_SHA256("RSA-PSS-SHA256-MGF1-SHA256"),
    RSA_PSS_SHA384_MGF1_SHA384("RSA-PSS-SHA384-MGF1-SHA384"),
    RSA_PSS_SHA512_MGF1_SHA512("RSA-PSS-SHA512-MGF1-SHA512"),
    ML_DSA_44("ML-DSA-44"),
    ML_DSA_65("ML-DSA-65"),
    ML_DSA_87("ML-DSA-87"),
    SLH_DSA_SHA2_128S("SLH-DSA-SHA2-128s"),
}

public enum class ReallyMeHashAlgorithm(public val algorithmName: String) {
    SHA2_256("SHA2-256"),
    SHA2_384("SHA2-384"),
    SHA2_512("SHA2-512"),
    SHA3_224("SHA3-224"),
    SHA3_256("SHA3-256"),
    SHA3_384("SHA3-384"),
    SHA3_512("SHA3-512"),
}

public enum class ReallyMeAeadAlgorithm(public val algorithmName: String) {
    AES_256_GCM("AES-256-GCM"),
    AES_256_GCM_SIV("AES-256-GCM-SIV"),
    CHACHA20_POLY1305("ChaCha20-Poly1305"),
    XCHACHA20_POLY1305("XChaCha20-Poly1305"),
}

public enum class ReallyMeKemAlgorithm(public val algorithmName: String) {
    ML_KEM_512("ML-KEM-512"),
    ML_KEM_768("ML-KEM-768"),
    ML_KEM_1024("ML-KEM-1024"),
    X_WING_768("X-Wing-768"),
    X_WING_1024("X-Wing-1024"),
}

public enum class ReallyMeKeyAgreementAlgorithm(public val algorithmName: String) {
    X25519("X25519"),
    P256_ECDH("P-256-ECDH"),
}

public enum class ReallyMeMacAlgorithm(public val algorithmName: String) {
    HMAC_SHA256("HMAC-SHA-256"),
    HMAC_SHA512("HMAC-SHA-512"),
}

public enum class ReallyMeKdfAlgorithm(public val algorithmName: String) {
    HKDF_SHA256("HKDF-SHA256"),
    ARGON2ID("Argon2id"),
    PBKDF2_HMAC_SHA256("PBKDF2-HMAC-SHA-256"),
    PBKDF2_HMAC_SHA512("PBKDF2-HMAC-SHA-512"),
}

public enum class ReallyMeKeyWrapAlgorithm(public val algorithmName: String) {
    AES_256_KW("AES-256-KW"),
}

public enum class ReallyMeHpkeSuite(public val algorithmName: String) {
    DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM(
        "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
    ),
    DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305(
        "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305",
    ),
}
