// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

/**
 * Raw P-521 ECDH through the Rust operation owner.
 *
 * The boundary accepts compressed SEC1 peer keys and returns the fixed-width
 * x-coordinate. Protocols must bind their own context through a labelled KDF.
 * Missing Rust providers fail closed; scalar arithmetic never runs in the JVM.
 */
public object ReallyMeP521Ecdh {
    public const val SECRET_KEY_LENGTH: Int = 66
    public const val COMPRESSED_PUBLIC_KEY_LENGTH: Int = 67
    public const val SHARED_SECRET_LENGTH: Int = 66
    private val ALGORITHM: ReallyMeKeyAgreementAlgorithm = ReallyMeKeyAgreementAlgorithm.P521_ECDH

    private const val SCALAR_HIGH_BYTE_MASK: Int = 0x01

    internal fun generateKeyPair(random: java.security.SecureRandom): Pair<ByteArray, ByteArray> =
        withRandomSecretCandidate(
            length = SECRET_KEY_LENGTH,
            random = random,
            prepareCandidate = { secretKey ->
                // Mask representation bits before rejection, without reduction.
                secretKey[0] = (secretKey[0].toInt() and SCALAR_HIGH_BYTE_MASK).toByte()
            },
            isValid = { ReallyMeRustKeyAgreement.isValidSecret(ALGORITHM, it) },
        ) { secretKey -> deriveKeyPair(secretKey) }

    public fun generateKeyPair(): Pair<ByteArray, ByteArray> =
        ReallyMeRustKeyAgreement.generateKeyPair(ALGORITHM)

    public fun deriveKeyPair(secretKey: ByteArray): Pair<ByteArray, ByteArray> =
        Pair(derivePublicKey(secretKey), secretKey.copyOf())

    public fun derivePublicKey(secretKey: ByteArray): ByteArray =
        ReallyMeRustKeyAgreement.derivePublicKey(ALGORITHM, secretKey)

    public fun deriveSharedSecret(publicKey: ByteArray, secretKey: ByteArray): ByteArray =
        ReallyMeRustKeyAgreement.deriveSharedSecret(ALGORITHM, publicKey, secretKey)
}
