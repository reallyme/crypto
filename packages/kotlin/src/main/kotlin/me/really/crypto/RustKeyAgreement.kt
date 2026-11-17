// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import me.really.crypto.proto.ReallyMeCryptoProtoAdapters

/** JNI transport for Rust-owned software P-curve key agreement. */
internal object ReallyMeRustKeyAgreement {
    private data class KeySizes(val publicLength: Int, val secretLength: Int, val sharedLength: Int)

    private fun sizes(algorithm: ReallyMeKeyAgreementAlgorithm): KeySizes = when (algorithm) {
        ReallyMeKeyAgreementAlgorithm.P256_ECDH -> KeySizes(ReallyMeP256Ecdh.COMPRESSED_PUBLIC_KEY_LENGTH, ReallyMeP256Ecdh.SECRET_KEY_LENGTH, ReallyMeP256Ecdh.SHARED_SECRET_LENGTH)
        ReallyMeKeyAgreementAlgorithm.P384_ECDH -> KeySizes(ReallyMeP384Ecdh.COMPRESSED_PUBLIC_KEY_LENGTH, ReallyMeP384Ecdh.SECRET_KEY_LENGTH, ReallyMeP384Ecdh.SHARED_SECRET_LENGTH)
        ReallyMeKeyAgreementAlgorithm.P521_ECDH -> KeySizes(ReallyMeP521Ecdh.COMPRESSED_PUBLIC_KEY_LENGTH, ReallyMeP521Ecdh.SECRET_KEY_LENGTH, ReallyMeP521Ecdh.SHARED_SECRET_LENGTH)
        ReallyMeKeyAgreementAlgorithm.X25519 -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
    }

    fun generateKeyPair(algorithm: ReallyMeKeyAgreementAlgorithm): Pair<ByteArray, ByteArray> {
        val sizes = sizes(algorithm)
        return ReallyMeRustProtocols.decodePair(
            ReallyMeRustProtocols.invoke { generateKeyPairNative(ReallyMeCryptoProtoAdapters.toProto(algorithm).number) },
            sizes.publicLength,
            sizes.secretLength,
        )
    }

    fun derivePublicKey(algorithm: ReallyMeKeyAgreementAlgorithm, secretKey: ByteArray): ByteArray {
        val sizes = sizes(algorithm)
        if (secretKey.size != sizes.secretLength) throw ReallyMeCryptoException.InvalidInput()
        return requireLength(
            ReallyMeRustProtocols.invoke { derivePublicKeyNative(ReallyMeCryptoProtoAdapters.toProto(algorithm).number, secretKey) },
            sizes.publicLength,
        )
    }

    fun deriveSharedSecret(
        algorithm: ReallyMeKeyAgreementAlgorithm,
        publicKey: ByteArray,
        secretKey: ByteArray,
    ): ByteArray {
        val sizes = sizes(algorithm)
        requireCompressedSec1PublicKey(publicKey, sizes.publicLength)
        if (secretKey.size != sizes.secretLength) throw ReallyMeCryptoException.InvalidInput()
        return requireLength(
            ReallyMeRustProtocols.invoke {
                deriveSharedSecretNative(ReallyMeCryptoProtoAdapters.toProto(algorithm).number, publicKey, secretKey)
            },
            sizes.sharedLength,
        )
    }

    // The injected-entropy seam uses the Rust importer for admission as well;
    // Kotlin never creates a secret JVM integer or multiplies a secret scalar.
    fun isValidSecret(algorithm: ReallyMeKeyAgreementAlgorithm, secretKey: ByteArray): Boolean = try {
        derivePublicKey(algorithm, secretKey).fill(0)
        true
    } catch (_: ReallyMeCryptoException.InvalidInput) {
        false
    }

    private fun requireLength(bytes: ByteArray, expected: Int): ByteArray {
        if (bytes.size != expected) {
            bytes.fill(0)
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return bytes
    }

    @JvmStatic
    private external fun generateKeyPairNative(algorithm: Int): ByteArray?
    @JvmStatic
    private external fun derivePublicKeyNative(algorithm: Int, secretKey: ByteArray): ByteArray?
    @JvmStatic
    private external fun deriveSharedSecretNative(algorithm: Int, publicKey: ByteArray, secretKey: ByteArray): ByteArray?
}
