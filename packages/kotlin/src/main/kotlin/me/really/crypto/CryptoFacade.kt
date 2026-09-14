// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

/**
 * Generic package facade. Algorithm-specific objects remain available for
 * callers that want direct provider access; this facade gives consumers a
 * stable typed route and rejects algorithm/operation combinations that the
 * selected method does not define.
 */
public object ReallyMeCrypto {
    /**
     * Executes one binary generated `CryptoOperationRequest`.
     *
     * The returned bytes are always a binary `CryptoOperationResponse` with a
     * generated `CryptoOperationResult` or generated `CryptoError` outcome.
     */
    @JvmStatic
    public fun processOperationResponse(request: ByteArray): ByteArray =
        ReallyMeCryptoSymmetricFacade.processOperationResponse(request)

    @JvmStatic
    public fun processOperationResponseJson(requestJson: ByteArray): ByteArray =
        ReallyMeCryptoSymmetricFacade.processOperationResponseJson(requestJson)

    @JvmStatic
    public fun hash(algorithm: ReallyMeHashAlgorithm, bytes: ByteArray): ByteArray =
        ReallyMeCryptoSymmetricFacade.hash(algorithm, bytes)

    @JvmStatic
    public fun seal(
        algorithm: ReallyMeAeadAlgorithm,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray = ReallyMeCryptoSymmetricFacade.seal(algorithm, key, nonce, aad, plaintext)

    @JvmStatic
    public fun open(
        algorithm: ReallyMeAeadAlgorithm,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextWithTag: ByteArray,
    ): ByteArray = ReallyMeCryptoSymmetricFacade.open(algorithm, key, nonce, aad, ciphertextWithTag)

    @JvmStatic
    public fun authenticate(
        algorithm: ReallyMeMacAlgorithm,
        key: ByteArray,
        message: ByteArray,
    ): ByteArray = ReallyMeCryptoSymmetricFacade.authenticate(algorithm, key, message)

    @JvmStatic
    public fun verifyMac(
        algorithm: ReallyMeMacAlgorithm,
        tag: ByteArray,
        key: ByteArray,
        message: ByteArray,
    ): Boolean = ReallyMeCryptoSymmetricFacade.verifyMac(algorithm, tag, key, message)

    @JvmStatic
    public fun deriveKey(
        algorithm: ReallyMeKdfAlgorithm,
        password: ByteArray,
        salt: ByteArray,
        iterations: UInt,
        outputLength: Int,
    ): ByteArray =
        ReallyMeCryptoSymmetricFacade.deriveKey(algorithm, password, salt, iterations, outputLength)

    @JvmStatic
    public fun deriveArgon2id(kdfVersion: UInt, secret: ByteArray, salt: ByteArray): ByteArray =
        ReallyMeCryptoSymmetricFacade.deriveArgon2id(kdfVersion, secret, salt)

    @JvmStatic
    public fun deriveHkdf(
        algorithm: ReallyMeKdfAlgorithm,
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int,
    ): ByteArray =
        ReallyMeCryptoSymmetricFacade.deriveHkdf(
            algorithm,
            inputKeyMaterial,
            salt,
            info,
            outputLength,
        )

    @JvmStatic
    public fun deriveJwaConcatKdfSha256(
        algorithm: ReallyMeKdfAlgorithm,
        sharedSecret: ByteArray,
        algorithmId: ByteArray,
        partyUInfo: ByteArray,
        partyVInfo: ByteArray,
        outputLength: Int,
    ): ByteArray =
        ReallyMeCryptoSymmetricFacade.deriveJwaConcatKdfSha256(
            algorithm,
            sharedSecret,
            algorithmId,
            partyUInfo,
            partyVInfo,
            outputLength,
        )

    @JvmStatic
    public fun deriveKmac256(
        algorithm: ReallyMeKdfAlgorithm,
        key: ByteArray,
        context: ByteArray,
        customization: ByteArray,
        outputLength: Int,
    ): ByteArray =
        ReallyMeCryptoSymmetricFacade.deriveKmac256(
            algorithm,
            key,
            context,
            customization,
            outputLength,
        )

    @JvmStatic
    public fun wrapKey(
        algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: ByteArray,
        keyToWrap: ByteArray,
    ): ByteArray = ReallyMeCryptoSymmetricFacade.wrapKey(algorithm, wrappingKey, keyToWrap)

    @JvmStatic
    public fun unwrapKey(
        algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: ByteArray,
        wrappedKey: ByteArray,
    ): ByteArray = ReallyMeCryptoSymmetricFacade.unwrapKey(algorithm, wrappingKey, wrappedKey)

    @JvmStatic
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

    @JvmStatic
    public fun deriveMlDsaKeyPair(
        algorithm: ReallyMeSignatureAlgorithm,
        secretSeed: ByteArray,
    ): ReallyMeSignatureKeyPair {
        val (publicKey, returnedSecretSeed) = ReallyMeMlDsa.deriveKeyPair(algorithm, secretSeed)
        return ReallyMeSignatureKeyPair(publicKey = publicKey, secretKey = returnedSecretSeed)
    }

    @JvmStatic
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

    @JvmStatic
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

    @JvmStatic
    public fun signBip340Schnorr(
        message32: ByteArray,
        secretKey: ByteArray,
        auxRand32: ByteArray,
    ): ByteArray =
        ReallyMeBip340Schnorr.sign(message32, secretKey, auxRand32)

    @JvmStatic
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

    @JvmStatic
    public fun verify(
        algorithm: ReallyMeSignatureAlgorithm,
        signature: ByteArray,
        message: ByteArray,
        publicKeyDer: ByteArray,
        publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding,
    ) {
        ReallyMeRsa.verify(algorithm, signature, message, publicKeyDer, publicKeyEncoding)
    }

    @JvmStatic
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

    @JvmStatic
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

    @JvmStatic
    public fun generateKemKeyPair(algorithm: ReallyMeKemAlgorithm): ReallyMeKemKeyPair =
        when (algorithm) {
            ReallyMeKemAlgorithm.ML_KEM_512,
            ReallyMeKemAlgorithm.ML_KEM_768,
            ReallyMeKemAlgorithm.ML_KEM_1024,
            -> {
                val (publicKey, secretKey) = ReallyMeMlKem.generateKeyPair(algorithm)
                ReallyMeKemKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
            ReallyMeKemAlgorithm.X_WING_768 -> {
                val (publicKey, secretKey) = ReallyMeXWing.generateKeyPair(algorithm)
                ReallyMeKemKeyPair(publicKey = publicKey, secretKey = secretKey)
            }
        }

    @JvmStatic
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
            ReallyMeKemAlgorithm.X_WING_768 -> {
                val publicKey = ReallyMeXWing.derivePublicKey(algorithm, secretKey)
                ReallyMeKemKeyPair(publicKey = publicKey, secretKey = secretKey.copyOf())
            }
        }

    @JvmStatic
    public fun encapsulate(
        algorithm: ReallyMeKemAlgorithm,
        publicKey: ByteArray,
    ): ReallyMeKemEncapsulation =
        when (algorithm) {
            ReallyMeKemAlgorithm.ML_KEM_512,
            ReallyMeKemAlgorithm.ML_KEM_768,
            ReallyMeKemAlgorithm.ML_KEM_1024,
            -> ReallyMeMlKem.encapsulate(algorithm, publicKey)
            ReallyMeKemAlgorithm.X_WING_768 -> ReallyMeXWing.encapsulate(algorithm, publicKey)
        }

    @JvmStatic
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
            ReallyMeKemAlgorithm.X_WING_768 -> ReallyMeXWing.encapsulateDeterministicForTest(algorithm, publicKey, seed)
        }

    @JvmStatic
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
            ReallyMeKemAlgorithm.X_WING_768 -> ReallyMeXWing.decapsulate(algorithm, ciphertext, secretKey)
        }

    @JvmStatic
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

    @JvmStatic
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
