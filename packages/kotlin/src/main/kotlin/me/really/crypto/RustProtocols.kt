// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import me.really.crypto.proto.ReallyMeCryptoProtoAdapters

/** JNI transport only: algorithm and protocol behavior belongs to Rust. */
internal object ReallyMeRustProtocols {
    internal fun invoke(operation: () -> ByteArray?): ByteArray {
        try {
            ReallyMeRustNativeProvider.requireLoaded()
        } catch (_: ReallyMeCryptoException.ProviderFailure) {
            throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }
        return try {
            requireRustNativeBytes(operation())
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: LinkageError) {
            throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: RuntimeException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    internal fun signatureKeyPair(
        algorithm: ReallyMeSignatureAlgorithm,
        secret: ByteArray?,
        publicLength: Int,
        secretLength: Int,
    ): Pair<ByteArray, ByteArray> = decodePair(
        invoke { signatureKeyPairNative(ReallyMeCryptoProtoAdapters.toProto(algorithm).number, secret) },
        publicLength,
        secretLength,
    )

    internal fun kemKeyPair(
        algorithm: ReallyMeKemAlgorithm,
        secret: ByteArray?,
        publicLength: Int,
        secretLength: Int,
    ): Pair<ByteArray, ByteArray> = decodePair(
        invoke { kemKeyPairNative(ReallyMeCryptoProtoAdapters.toProto(algorithm).number, secret) },
        publicLength,
        secretLength,
    )

    internal fun sign(algorithm: ReallyMeSignatureAlgorithm, secret: ByteArray, message: ByteArray): ByteArray =
        invoke { signNative(ReallyMeCryptoProtoAdapters.toProto(algorithm).number, secret, message) }

    internal fun verify(
        algorithm: ReallyMeSignatureAlgorithm,
        publicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ) {
        val output = invoke { verifyNative(ReallyMeCryptoProtoAdapters.toProto(algorithm).number, publicKey, message, signature) }
        try {
            if (output.isNotEmpty()) throw ReallyMeCryptoException.ProviderFailure()
        } finally {
            output.fill(0)
        }
    }

    internal fun encapsulate(
        algorithm: ReallyMeKemAlgorithm,
        publicKey: ByteArray,
        ciphertextLength: Int,
    ): ReallyMeKemEncapsulation {
        val encoded = invoke { encapsulateNative(ReallyMeCryptoProtoAdapters.toProto(algorithm).number, publicKey) }
        val (ciphertext, secret) = decodePair(encoded, ciphertextLength, SHARED_SECRET_LENGTH)
        return ReallyMeKemEncapsulation(sharedSecret = secret, ciphertext = ciphertext)
    }

    internal fun decapsulate(algorithm: ReallyMeKemAlgorithm, ciphertext: ByteArray, secret: ByteArray): ByteArray =
        requireOutputLength(
            invoke { decapsulateNative(ReallyMeCryptoProtoAdapters.toProto(algorithm).number, ciphertext, secret) },
            SHARED_SECRET_LENGTH,
        )

    internal fun seal(
        suite: ReallyMeHpkeSuite,
        publicKey: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
        encapsulatedLength: Int,
    ): ReallyMeHpkeSealedMessage {
        val ids = ReallyMeCryptoProtoAdapters.toProto(suite)
        val ciphertextLength = checkedLength(plaintext.size, HPKE_TAG_LENGTH)
        val encoded = invoke { hpkeSealNative(ids.kemValue, ids.kdfValue, ids.aeadValue, publicKey, info, aad, plaintext) }
        val (encapsulated, ciphertext) = decodePair(encoded, encapsulatedLength, ciphertextLength)
        return ReallyMeHpkeSealedMessage(encapsulatedKey = encapsulated, ciphertext = ciphertext)
    }

    internal fun open(
        suite: ReallyMeHpkeSuite,
        secret: ByteArray,
        encapsulated: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val ids = ReallyMeCryptoProtoAdapters.toProto(suite)
        val output = invoke { hpkeOpenNative(ids.kemValue, ids.kdfValue, ids.aeadValue, secret, encapsulated, info, aad, ciphertext) }
        return requireOutputLength(output, Math.subtractExact(ciphertext.size, HPKE_TAG_LENGTH))
    }

    private fun requireOutputLength(bytes: ByteArray, length: Int): ByteArray {
        if (bytes.size != length) {
            bytes.fill(0)
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return bytes
    }

    // JNI results contain only two fixed-width components. Validate the complete
    // shape before copying, and erase the transport copy even if decoding fails.
    internal fun decodePair(bytes: ByteArray, firstLength: Int, secondLength: Int): Pair<ByteArray, ByteArray> {
        try {
            if (firstLength < 0 || secondLength < 0 || bytes.size != checkedLength(firstLength, secondLength)) {
                throw ReallyMeCryptoException.ProviderFailure()
            }
            val first = bytes.copyOfRange(0, firstLength)
            return try {
                Pair(first, bytes.copyOfRange(firstLength, bytes.size))
            } catch (_: RuntimeException) {
                first.fill(0)
                throw ReallyMeCryptoException.ProviderFailure()
            }
        } finally {
            bytes.fill(0)
        }
    }

    private fun checkedLength(first: Int, second: Int): Int = try {
        Math.addExact(first, second)
    } catch (_: ArithmeticException) {
        throw ReallyMeCryptoException.ProviderFailure()
    }

    private const val SHARED_SECRET_LENGTH: Int = 32
    private const val HPKE_TAG_LENGTH: Int = 16

    @JvmStatic
    private external fun signatureKeyPairNative(algorithm: Int, secret: ByteArray?): ByteArray?
    @JvmStatic
    private external fun kemKeyPairNative(algorithm: Int, secret: ByteArray?): ByteArray?
    @JvmStatic
    private external fun signNative(algorithm: Int, secret: ByteArray, message: ByteArray): ByteArray?
    @JvmStatic
    private external fun verifyNative(
        algorithm: Int,
        publicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): ByteArray?
    @JvmStatic
    private external fun encapsulateNative(algorithm: Int, publicKey: ByteArray): ByteArray?
    @JvmStatic
    private external fun decapsulateNative(algorithm: Int, ciphertext: ByteArray, secret: ByteArray): ByteArray?
    @JvmStatic
    private external fun hpkeSealNative(
        kem: Int,
        kdf: Int,
        aead: Int,
        publicKey: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray?
    @JvmStatic
    private external fun hpkeOpenNative(
        kem: Int,
        kdf: Int,
        aead: Int,
        secret: ByteArray,
        encapsulated: ByteArray,
        info: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray?
}
