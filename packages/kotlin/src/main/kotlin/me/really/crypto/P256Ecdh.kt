// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

/**
 * Raw P-256 ECDH through the Rust operation owner.
 *
 * The boundary accepts compressed SEC1 peer keys and returns the fixed-width
 * x-coordinate. Protocols must bind their own context through a labelled KDF.
 * Missing Rust providers fail closed; scalar arithmetic never runs in the JVM.
 */
public object ReallyMeP256Ecdh {
    public const val SECRET_KEY_LENGTH: Int = 32
    public const val COMPRESSED_PUBLIC_KEY_LENGTH: Int = 33
    public const val SHARED_SECRET_LENGTH: Int = 32
    private val ALGORITHM: ReallyMeKeyAgreementAlgorithm = ReallyMeKeyAgreementAlgorithm.P256_ECDH

    public fun generateKeyPair(): Pair<ByteArray, ByteArray> =
        ReallyMeRustKeyAgreement.generateKeyPair(ALGORITHM)

    public fun deriveKeyPair(secretKey: ByteArray): Pair<ByteArray, ByteArray> =
        Pair(derivePublicKey(secretKey), secretKey.copyOf())

    public fun derivePublicKey(secretKey: ByteArray): ByteArray =
        ReallyMeRustKeyAgreement.derivePublicKey(ALGORITHM, secretKey)

    public fun deriveSharedSecret(publicKey: ByteArray, secretKey: ByteArray): ByteArray =
        ReallyMeRustKeyAgreement.deriveSharedSecret(ALGORITHM, publicKey, secretKey)
}
