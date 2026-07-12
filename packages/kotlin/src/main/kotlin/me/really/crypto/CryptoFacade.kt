// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

public data class ReallyMeSignatureKeyPair(
    public val publicKey: ByteArray,
    public val secretKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeSignatureKeyPair &&
            publicKey.contentEquals(other.publicKey) &&
            secretKey.contentEquals(other.secretKey)

    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + secretKey.contentHashCode()
}

public class ReallyMeKemKeyPair(
    public val publicKey: ByteArray,
    public val secretKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeKemKeyPair &&
            publicKey.contentEquals(other.publicKey) &&
            secretKey.contentEquals(other.secretKey)

    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + secretKey.contentHashCode()
}

public class ReallyMeKeyAgreementKeyPair(
    public val publicKey: ByteArray,
    public val secretKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeKeyAgreementKeyPair &&
            publicKey.contentEquals(other.publicKey) &&
            secretKey.contentEquals(other.secretKey)

    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + secretKey.contentHashCode()
}

public class ReallyMeKemEncapsulation(
    public val sharedSecret: ByteArray,
    public val ciphertext: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeKemEncapsulation &&
            sharedSecret.contentEquals(other.sharedSecret) &&
            ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int = 31 * sharedSecret.contentHashCode() + ciphertext.contentHashCode()
}

public class ReallyMeHpkeSealedMessage(
    public val encapsulatedKey: ByteArray,
    public val ciphertext: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeHpkeSealedMessage &&
            encapsulatedKey.contentEquals(other.encapsulatedKey) &&
            ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int = 31 * encapsulatedKey.contentHashCode() + ciphertext.contentHashCode()
}

/**
 * Generic package facade. Algorithm-specific objects remain available for
 * callers that want direct provider access; this facade gives consumers a
 * stable typed route that fails closed for not-yet-exposed algorithms.
 */
public object ReallyMeCrypto {
    public fun hash(algorithm: ReallyMeHashAlgorithm, bytes: ByteArray): ByteArray =
        when (algorithm) {
            ReallyMeHashAlgorithm.SHA2_256 -> ReallyMeDigest.sha256(bytes)
            ReallyMeHashAlgorithm.SHA2_384 -> ReallyMeDigest.sha384(bytes)
            ReallyMeHashAlgorithm.SHA2_512 -> ReallyMeDigest.sha512(bytes)
            ReallyMeHashAlgorithm.SHA3_224 -> ReallyMeDigest.sha3_224(bytes)
            ReallyMeHashAlgorithm.SHA3_256 -> ReallyMeDigest.sha3_256(bytes)
            ReallyMeHashAlgorithm.SHA3_384 -> ReallyMeDigest.sha3_384(bytes)
            ReallyMeHashAlgorithm.SHA3_512 -> ReallyMeDigest.sha3_512(bytes)
        }

    public fun seal(
        algorithm: ReallyMeAeadAlgorithm,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeAeadAlgorithm.AES_128_GCM -> ReallyMeAesGcm.sealAes128Gcm(key, nonce, aad, plaintext)
            ReallyMeAeadAlgorithm.AES_192_GCM -> ReallyMeAesGcm.sealAes192Gcm(key, nonce, aad, plaintext)
            ReallyMeAeadAlgorithm.AES_256_GCM -> ReallyMeAesGcm.seal(key, nonce, aad, plaintext)
            ReallyMeAeadAlgorithm.AES_256_GCM_SIV ->
                ReallyMeRustAead.sealAes256GcmSiv(key, nonce, aad, plaintext)
            ReallyMeAeadAlgorithm.CHACHA20_POLY1305 ->
                ReallyMeRustAead.sealChaCha20Poly1305(key, nonce, aad, plaintext)
            ReallyMeAeadAlgorithm.XCHACHA20_POLY1305 ->
                ReallyMeRustAead.sealXChaCha20Poly1305(key, nonce, aad, plaintext)
        }

    public fun open(
        algorithm: ReallyMeAeadAlgorithm,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeAeadAlgorithm.AES_128_GCM ->
                ReallyMeAesGcm.openAes128Gcm(key, nonce, aad, ciphertextWithTag)
            ReallyMeAeadAlgorithm.AES_192_GCM ->
                ReallyMeAesGcm.openAes192Gcm(key, nonce, aad, ciphertextWithTag)
            ReallyMeAeadAlgorithm.AES_256_GCM -> ReallyMeAesGcm.open(key, nonce, aad, ciphertextWithTag)
            ReallyMeAeadAlgorithm.AES_256_GCM_SIV ->
                ReallyMeRustAead.openAes256GcmSiv(key, nonce, aad, ciphertextWithTag)
            ReallyMeAeadAlgorithm.CHACHA20_POLY1305 ->
                ReallyMeRustAead.openChaCha20Poly1305(key, nonce, aad, ciphertextWithTag)
            ReallyMeAeadAlgorithm.XCHACHA20_POLY1305 ->
                ReallyMeRustAead.openXChaCha20Poly1305(key, nonce, aad, ciphertextWithTag)
        }

    public fun authenticate(
        algorithm: ReallyMeMacAlgorithm,
        key: ByteArray,
        message: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeMacAlgorithm.HMAC_SHA256 -> ReallyMeHmac.authenticateSha256(key, message)
            ReallyMeMacAlgorithm.HMAC_SHA512 -> ReallyMeHmac.authenticateSha512(key, message)
        }

    public fun verifyMac(
        algorithm: ReallyMeMacAlgorithm,
        tag: ByteArray,
        key: ByteArray,
        message: ByteArray,
    ): Boolean =
        when (algorithm) {
            ReallyMeMacAlgorithm.HMAC_SHA256 -> ReallyMeHmac.verifySha256(tag, key, message)
            ReallyMeMacAlgorithm.HMAC_SHA512 -> ReallyMeHmac.verifySha512(tag, key, message)
        }

    public fun deriveKey(
        algorithm: ReallyMeKdfAlgorithm,
        password: ByteArray,
        salt: ByteArray,
        iterations: UInt,
        outputLength: Int,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256 ->
                ReallyMePbkdf2.deriveHmacSha256(password, salt, iterations, outputLength)
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512 ->
                ReallyMePbkdf2.deriveHmacSha512(password, salt, iterations, outputLength)
            ReallyMeKdfAlgorithm.ARGON2ID -> {
                if (outputLength != ReallyMeArgon2id.DERIVED_KEY_LENGTH) {
                    throw ReallyMeCryptoException.InvalidInput()
                }
                ReallyMeArgon2id.deriveKey(iterations, password, salt)
            }
            ReallyMeKdfAlgorithm.HKDF_SHA256,
            ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256,
            -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun deriveHkdf(
        algorithm: ReallyMeKdfAlgorithm,
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKdfAlgorithm.HKDF_SHA256 ->
                ReallyMeHkdf.deriveSha256(inputKeyMaterial, salt, info, outputLength)
            ReallyMeKdfAlgorithm.ARGON2ID,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512,
            ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256,
            -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun deriveJwaConcatKdfSha256(
        algorithm: ReallyMeKdfAlgorithm,
        sharedSecret: ByteArray,
        algorithmId: ByteArray,
        partyUInfo: ByteArray,
        partyVInfo: ByteArray,
        outputLength: Int,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256 ->
                ReallyMeJwaConcatKdf.deriveSha256(
                    sharedSecret,
                    algorithmId,
                    partyUInfo,
                    partyVInfo,
                    outputLength,
                )
            ReallyMeKdfAlgorithm.ARGON2ID,
            ReallyMeKdfAlgorithm.HKDF_SHA256,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512,
            -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun wrapKey(
        algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: ByteArray,
        keyToWrap: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKeyWrapAlgorithm.AES_256_KW -> ReallyMeAesKw.wrapKey(wrappingKey, keyToWrap)
        }

    public fun unwrapKey(
        algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: ByteArray,
        wrappedKey: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKeyWrapAlgorithm.AES_256_KW -> ReallyMeAesKw.unwrapKey(wrappingKey, wrappedKey)
        }

    public fun generateKeyPair(algorithm: ReallyMeSignatureAlgorithm): ReallyMeSignatureKeyPair =
        when (algorithm) {
            ReallyMeSignatureAlgorithm.ED25519 -> {
                val (publicKey, secretKey) = ReallyMeEd25519.generateKeyPair()
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256 -> {
                val (publicKey, secretKey) = ReallyMeP256Ecdsa.generateKeyPair()
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
            ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384 -> {
                val (publicKey, secretKey) = ReallyMeP384Ecdsa.generateKeyPair()
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
            ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512 -> {
                val (publicKey, secretKey) = ReallyMeP521Ecdsa.generateKeyPair()
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
            ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256 -> {
                val (publicKey, secretKey) = ReallyMeSecp256k1.generateKeyPair()
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
            ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256 -> {
                val (publicKey, secretKey) = ReallyMeBip340Schnorr.generateKeyPair()
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
            ReallyMeSignatureAlgorithm.ML_DSA_44,
            ReallyMeSignatureAlgorithm.ML_DSA_65,
            ReallyMeSignatureAlgorithm.ML_DSA_87,
            -> {
                val (publicKey, secretKey) = ReallyMeMlDsa.generateKeyPair(algorithm)
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S -> {
                val (publicKey, secretKey) = ReallyMeSlhDsa.generateKeyPair(algorithm)
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun deriveMlDsaKeyPair(
        algorithm: ReallyMeSignatureAlgorithm,
        secretSeed: ByteArray,
    ): ReallyMeSignatureKeyPair {
        val (publicKey, returnedSecretSeed) = ReallyMeMlDsa.deriveKeyPair(algorithm, secretSeed)
        return ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = returnedSecretSeed)
    }

    public fun deriveKeyPair(
        algorithm: ReallyMeSignatureAlgorithm,
        secretKey: ByteArray,
    ): ReallyMeSignatureKeyPair =
        when (algorithm) {
            ReallyMeSignatureAlgorithm.ED25519 -> {
                val (publicKey, returnedSecretKey) = ReallyMeEd25519.deriveKeyPair(secretKey)
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256 -> {
                val (publicKey, returnedSecretKey) = ReallyMeP256Ecdsa.deriveKeyPair(secretKey)
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384 -> {
                val (publicKey, returnedSecretKey) = ReallyMeP384Ecdsa.deriveKeyPair(secretKey)
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512 -> {
                val (publicKey, returnedSecretKey) = ReallyMeP521Ecdsa.deriveKeyPair(secretKey)
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256 -> {
                val (publicKey, returnedSecretKey) = ReallyMeSecp256k1.deriveKeyPair(secretKey)
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256 -> {
                val (publicKey, returnedSecretKey) = ReallyMeBip340Schnorr.deriveKeyPair(secretKey)
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            ReallyMeSignatureAlgorithm.ML_DSA_44,
            ReallyMeSignatureAlgorithm.ML_DSA_65,
            ReallyMeSignatureAlgorithm.ML_DSA_87,
            -> {
                val (publicKey, returnedSecretKey) = ReallyMeMlDsa.deriveKeyPair(algorithm, secretKey)
                ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun sign(
        algorithm: ReallyMeSignatureAlgorithm,
        message: ByteArray,
        secretKey: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeSignatureAlgorithm.ED25519 ->
                ReallyMeEd25519.sign(message, secretKey)
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256 ->
                ReallyMeP256Ecdsa.sign(message, secretKey)
            ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384 ->
                ReallyMeP384Ecdsa.sign(message, secretKey)
            ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512 ->
                ReallyMeP521Ecdsa.sign(message, secretKey)
            ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256 ->
                ReallyMeSecp256k1.sign(message, secretKey)
            ReallyMeSignatureAlgorithm.ML_DSA_44,
            ReallyMeSignatureAlgorithm.ML_DSA_65,
            ReallyMeSignatureAlgorithm.ML_DSA_87,
            -> ReallyMeMlDsa.sign(algorithm, message, secretKey)
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S ->
                ReallyMeSlhDsa.sign(algorithm, message, secretKey)
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun signBip340Schnorr(
        message32: ByteArray,
        secretKey: ByteArray,
        auxRand32: ByteArray,
    ): ByteArray =
        ReallyMeBip340Schnorr.sign(message32, secretKey, auxRand32)

    public fun verify(
        algorithm: ReallyMeSignatureAlgorithm,
        signature: ByteArray,
        message: ByteArray,
        publicKey: ByteArray,
    ) {
        when (algorithm) {
            ReallyMeSignatureAlgorithm.ED25519 ->
                ReallyMeEd25519.verify(signature, message, publicKey)
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256 ->
                ReallyMeP256Ecdsa.verify(signature, message, publicKey)
            ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384 ->
                ReallyMeP384Ecdsa.verify(signature, message, publicKey)
            ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512 ->
                ReallyMeP521Ecdsa.verify(signature, message, publicKey)
            ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256 ->
                ReallyMeSecp256k1.verify(signature, message, publicKey)
            ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256 ->
                ReallyMeBip340Schnorr.verify(signature, message, publicKey)
            ReallyMeSignatureAlgorithm.ML_DSA_44,
            ReallyMeSignatureAlgorithm.ML_DSA_65,
            ReallyMeSignatureAlgorithm.ML_DSA_87,
            -> ReallyMeMlDsa.verify(algorithm, signature, message, publicKey)
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S ->
                ReallyMeSlhDsa.verify(algorithm, signature, message, publicKey)
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }
    }

    public fun verify(
        algorithm: ReallyMeSignatureAlgorithm,
        signature: ByteArray,
        message: ByteArray,
        publicKeyDer: ByteArray,
        publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding,
    ) {
        ReallyMeRsa.verify(algorithm, signature, message, publicKeyDer, publicKeyEncoding)
    }

    public fun deriveSharedSecret(
        algorithm: ReallyMeKeyAgreementAlgorithm,
        publicKey: ByteArray,
        secretKey: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKeyAgreementAlgorithm.X25519 ->
                ReallyMeX25519.deriveSharedSecret(publicKey, secretKey)
            ReallyMeKeyAgreementAlgorithm.P256_ECDH ->
                ReallyMeP256Ecdh.deriveSharedSecret(publicKey, secretKey)
            ReallyMeKeyAgreementAlgorithm.P384_ECDH ->
                ReallyMeP384Ecdh.deriveSharedSecret(publicKey, secretKey)
            ReallyMeKeyAgreementAlgorithm.P521_ECDH ->
                ReallyMeP521Ecdh.deriveSharedSecret(publicKey, secretKey)
        }

    public fun deriveKeyAgreementKeyPair(
        algorithm: ReallyMeKeyAgreementAlgorithm,
        secretKey: ByteArray,
    ): ReallyMeKeyAgreementKeyPair =
        when (algorithm) {
            ReallyMeKeyAgreementAlgorithm.X25519 -> {
                val (publicKey, returnedSecretKey) = ReallyMeX25519.deriveKeyPair(secretKey)
                ReallyMeKeyAgreementKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            ReallyMeKeyAgreementAlgorithm.P256_ECDH -> {
                val (publicKey, returnedSecretKey) = ReallyMeP256Ecdh.deriveKeyPair(secretKey)
                ReallyMeKeyAgreementKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            ReallyMeKeyAgreementAlgorithm.P384_ECDH -> {
                val (publicKey, returnedSecretKey) = ReallyMeP384Ecdh.deriveKeyPair(secretKey)
                ReallyMeKeyAgreementKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            ReallyMeKeyAgreementAlgorithm.P521_ECDH -> {
                val (publicKey, returnedSecretKey) = ReallyMeP521Ecdh.deriveKeyPair(secretKey)
                ReallyMeKeyAgreementKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
        }

    public fun generateKemKeyPair(algorithm: ReallyMeKemAlgorithm): ReallyMeKemKeyPair =
        when (algorithm) {
            ReallyMeKemAlgorithm.ML_KEM_512,
            ReallyMeKemAlgorithm.ML_KEM_768,
            ReallyMeKemAlgorithm.ML_KEM_1024,
            -> {
                val (publicKey, secretKey) = ReallyMeMlKem.generateKeyPair(algorithm)
                ReallyMeKemKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
            ReallyMeKemAlgorithm.X_WING_768,
            ReallyMeKemAlgorithm.X_WING_1024,
            -> {
                val (publicKey, secretKey) = ReallyMeXWing.generateKeyPair(algorithm)
                ReallyMeKemKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
        }

    public fun deriveKemKeyPair(
        algorithm: ReallyMeKemAlgorithm,
        secretKey: ByteArray,
    ): ReallyMeKemKeyPair =
        when (algorithm) {
            ReallyMeKemAlgorithm.ML_KEM_512,
            ReallyMeKemAlgorithm.ML_KEM_768,
            ReallyMeKemAlgorithm.ML_KEM_1024,
            -> {
                val (publicKey, returnedSecretKey) = ReallyMeMlKem.deriveKeyPair(algorithm, secretKey)
                ReallyMeKemKeyPair(publicKey = publicKey, secretKey = returnedSecretKey)
            }
            ReallyMeKemAlgorithm.X_WING_768,
            ReallyMeKemAlgorithm.X_WING_1024,
            -> {
                val publicKey = ReallyMeXWing.derivePublicKey(algorithm, secretKey)
                ReallyMeKemKeyPair(publicKey = publicKey, secretKey = secretKey.copyOf())
            }
        }

    public fun encapsulate(
        algorithm: ReallyMeKemAlgorithm,
        publicKey: ByteArray,
    ): ReallyMeKemEncapsulation =
        when (algorithm) {
            ReallyMeKemAlgorithm.ML_KEM_512,
            ReallyMeKemAlgorithm.ML_KEM_768,
            ReallyMeKemAlgorithm.ML_KEM_1024,
            -> ReallyMeMlKem.encapsulate(algorithm, publicKey)
            ReallyMeKemAlgorithm.X_WING_768,
            ReallyMeKemAlgorithm.X_WING_1024,
            -> ReallyMeXWing.encapsulate(algorithm, publicKey)
        }

    public fun encapsulateDeterministicForTest(
        algorithm: ReallyMeKemAlgorithm,
        publicKey: ByteArray,
        seed: ByteArray,
    ): ReallyMeKemEncapsulation =
        when (algorithm) {
            ReallyMeKemAlgorithm.ML_KEM_512,
            ReallyMeKemAlgorithm.ML_KEM_768,
            ReallyMeKemAlgorithm.ML_KEM_1024,
            -> ReallyMeMlKem.encapsulateDeterministicForTest(algorithm, publicKey, seed)
            ReallyMeKemAlgorithm.X_WING_768,
            ReallyMeKemAlgorithm.X_WING_1024,
            -> ReallyMeXWing.encapsulateDeterministicForTest(algorithm, publicKey, seed)
        }

    public fun decapsulate(
        algorithm: ReallyMeKemAlgorithm,
        ciphertext: ByteArray,
        secretKey: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKemAlgorithm.ML_KEM_512,
            ReallyMeKemAlgorithm.ML_KEM_768,
            ReallyMeKemAlgorithm.ML_KEM_1024,
            -> ReallyMeMlKem.decapsulate(algorithm, ciphertext, secretKey)
            ReallyMeKemAlgorithm.X_WING_768,
            ReallyMeKemAlgorithm.X_WING_1024,
            -> ReallyMeXWing.decapsulate(algorithm, ciphertext, secretKey)
        }

    public fun sealHpke(
        suite: ReallyMeHpkeSuite,
        recipientPublicKey: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ReallyMeHpkeSealedMessage =
        when (suite) {
            ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM,
            ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
            -> ReallyMeHpke.seal(suite, recipientPublicKey, info, aad, plaintext)
        }

    public fun openHpke(
        suite: ReallyMeHpkeSuite,
        recipientSecretKey: ByteArray,
        encapsulatedKey: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray =
        when (suite) {
            ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM,
            ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
            -> ReallyMeHpke.open(suite, recipientSecretKey, encapsulatedKey, info, aad, ciphertext)
        }
}
