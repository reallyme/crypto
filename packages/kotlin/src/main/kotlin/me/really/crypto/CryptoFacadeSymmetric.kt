// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

internal object ReallyMeCryptoSymmetricFacade {
    internal fun processOperationResponse(request: ByteArray): ByteArray {
        ReallyMeRustNativeProvider.requireLoaded()
        return try {
            requireNativeOperationResponse(
                ReallyMeCryptoOperationResponseNative.processOperationResponseNative(request),
            )
        } catch (_: UnsatisfiedLinkError) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    /**
     * Executes a permitted non-secret generated ProtoJSON request.
     *
     * JSON is request-only; secret-bearing selectors fail before value
     * deserialization. Returned bytes use the same binary response as
     * [processOperationResponse].
     */
    internal fun processOperationResponseJson(requestJson: ByteArray): ByteArray {
        ReallyMeRustNativeProvider.requireLoaded()
        return try {
            requireNativeOperationResponse(
                ReallyMeCryptoOperationResponseNative.processOperationResponseJsonNative(requestJson),
            )
        } catch (_: UnsatisfiedLinkError) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    internal fun hash(algorithm: ReallyMeHashAlgorithm, bytes: ByteArray): ByteArray =
        when (algorithm) {
            ReallyMeHashAlgorithm.SHA2_256 -> ReallyMeDigest.sha256(bytes)
            ReallyMeHashAlgorithm.SHA2_384 -> ReallyMeDigest.sha384(bytes)
            ReallyMeHashAlgorithm.SHA2_512 -> ReallyMeDigest.sha512(bytes)
            ReallyMeHashAlgorithm.SHA3_224 -> ReallyMeDigest.sha3_224(bytes)
            ReallyMeHashAlgorithm.SHA3_256 -> ReallyMeDigest.sha3_256(bytes)
            ReallyMeHashAlgorithm.SHA3_384 -> ReallyMeDigest.sha3_384(bytes)
            ReallyMeHashAlgorithm.SHA3_512 -> ReallyMeDigest.sha3_512(bytes)
        }

    internal fun seal(
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

    internal fun open(
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

    internal fun authenticate(
        algorithm: ReallyMeMacAlgorithm,
        key: ByteArray,
        message: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeMacAlgorithm.HMAC_SHA256 -> ReallyMeHmac.authenticateSha256(key, message)
            ReallyMeMacAlgorithm.HMAC_SHA384 -> ReallyMeHmac.authenticateSha384(key, message)
            ReallyMeMacAlgorithm.HMAC_SHA512 -> ReallyMeHmac.authenticateSha512(key, message)
        }

    internal fun verifyMac(
        algorithm: ReallyMeMacAlgorithm,
        tag: ByteArray,
        key: ByteArray,
        message: ByteArray,
    ): Boolean =
        when (algorithm) {
            ReallyMeMacAlgorithm.HMAC_SHA256 -> ReallyMeHmac.verifySha256(tag, key, message)
            ReallyMeMacAlgorithm.HMAC_SHA384 -> ReallyMeHmac.verifySha384(tag, key, message)
            ReallyMeMacAlgorithm.HMAC_SHA512 -> ReallyMeHmac.verifySha512(tag, key, message)
        }

    internal fun deriveKey(
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
            ReallyMeKdfAlgorithm.ARGON2ID,
            ReallyMeKdfAlgorithm.HKDF_SHA256,
            ReallyMeKdfAlgorithm.HKDF_SHA384,
            ReallyMeKdfAlgorithm.KMAC256,
            ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256,
            -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    internal fun deriveArgon2id(
        kdfVersion: UInt,
        secret: ByteArray,
        salt: ByteArray,
    ): ByteArray = ReallyMeArgon2id.deriveKey(kdfVersion, secret, salt)

    internal fun deriveHkdf(
        algorithm: ReallyMeKdfAlgorithm,
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKdfAlgorithm.HKDF_SHA256 ->
                ReallyMeHkdf.deriveSha256(inputKeyMaterial, salt, info, outputLength)
            ReallyMeKdfAlgorithm.HKDF_SHA384 ->
                ReallyMeHkdf.deriveSha384(inputKeyMaterial, salt, info, outputLength)
            ReallyMeKdfAlgorithm.ARGON2ID,
            ReallyMeKdfAlgorithm.KMAC256,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512,
            ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256,
            -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    internal fun deriveJwaConcatKdfSha256(
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
            ReallyMeKdfAlgorithm.HKDF_SHA384,
            ReallyMeKdfAlgorithm.KMAC256,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512,
            -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    internal fun deriveKmac256(
        algorithm: ReallyMeKdfAlgorithm,
        key: ByteArray,
        context: ByteArray,
        customization: ByteArray,
        outputLength: Int,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKdfAlgorithm.KMAC256 ->
                ReallyMeKmac.deriveKmac256(key, context, customization, outputLength)
            ReallyMeKdfAlgorithm.ARGON2ID,
            ReallyMeKdfAlgorithm.HKDF_SHA256,
            ReallyMeKdfAlgorithm.HKDF_SHA384,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256,
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512,
            ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256,
            -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    internal fun wrapKey(
        algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: ByteArray,
        keyToWrap: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKeyWrapAlgorithm.AES_128_KW,
            ReallyMeKeyWrapAlgorithm.AES_192_KW,
            ReallyMeKeyWrapAlgorithm.AES_256_KW,
            -> ReallyMeAesKw.wrapKey(algorithm, wrappingKey, keyToWrap)
        }

    internal fun unwrapKey(
        algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: ByteArray,
        wrappedKey: ByteArray,
    ): ByteArray =
        when (algorithm) {
            ReallyMeKeyWrapAlgorithm.AES_128_KW,
            ReallyMeKeyWrapAlgorithm.AES_192_KW,
            ReallyMeKeyWrapAlgorithm.AES_256_KW,
            -> ReallyMeAesKw.unwrapKey(algorithm, wrappingKey, wrappedKey)
        }

}
