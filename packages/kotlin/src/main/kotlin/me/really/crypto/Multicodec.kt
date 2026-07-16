// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/**
 * Public-key multicodec identifiers recognized by the Kotlin package.
 *
 * These identifiers describe encoded key material. They do not imply that the
 * corresponding signing or KEM primitive is implemented in the Kotlin facade.
 */
public enum class ReallyMeMulticodecKeyAlgorithm(
    public val codecName: String,
    public val algorithmName: String,
    private val prefixBytes: ByteArray,
    public val expectedPublicKeyLength: Int?,
) {
    ED25519_PUBLIC_KEY("ed25519-pub", "Ed25519", byteArrayOf(0xed.toByte(), 0x01), 32),
    X25519_PUBLIC_KEY("x25519-pub", "X25519", byteArrayOf(0xec.toByte(), 0x01), 32),
    P256_PUBLIC_KEY("p256-pub", "P-256", byteArrayOf(0x80.toByte(), 0x24), 33),
    P384_PUBLIC_KEY("p384-pub", "P-384", byteArrayOf(0x81.toByte(), 0x24), 49),
    P521_PUBLIC_KEY("p521-pub", "P-521", byteArrayOf(0x82.toByte(), 0x24), 67),
    ED448_PUBLIC_KEY("ed448-pub", "Ed448", byteArrayOf(0x83.toByte(), 0x24), 57),
    RSA_PUBLIC_KEY("rsa-pub", "RSA", byteArrayOf(0x85.toByte(), 0x24), null),
    SECP256K1_PUBLIC_KEY("secp256k1-pub", "secp256k1", byteArrayOf(0xe7.toByte(), 0x01), 33),
    ML_DSA_44_PUBLIC_KEY("mldsa-44-pub", "ML-DSA-44", byteArrayOf(0x90.toByte(), 0x24), 1_312),
    ML_DSA_65_PUBLIC_KEY("mldsa-65-pub", "ML-DSA-65", byteArrayOf(0x91.toByte(), 0x24), 1_952),
    ML_DSA_87_PUBLIC_KEY("mldsa-87-pub", "ML-DSA-87", byteArrayOf(0x92.toByte(), 0x24), 2_592),
    ML_KEM_512_PUBLIC_KEY("mlkem-512-pub", "ML-KEM-512", byteArrayOf(0x8b.toByte(), 0x24), 800),
    ML_KEM_768_PUBLIC_KEY("mlkem-768-pub", "ML-KEM-768", byteArrayOf(0x8c.toByte(), 0x24), 1_184),
    ML_KEM_1024_PUBLIC_KEY("mlkem-1024-pub", "ML-KEM-1024", byteArrayOf(0x8d.toByte(), 0x24), 1_568),
    ;

    public fun prefix(): ByteArray = prefixBytes.copyOf()
}

public object ReallyMeMulticodec {
    public val publicKeyAlgorithms: List<ReallyMeMulticodecKeyAlgorithm> =
        ReallyMeMulticodecKeyAlgorithm.entries.toList()

    public fun codecName(algorithm: ReallyMeMulticodecKeyAlgorithm): String =
        algorithm.codecName

    public fun algorithmName(algorithm: ReallyMeMulticodecKeyAlgorithm): String =
        algorithm.algorithmName

    public fun prefix(algorithm: ReallyMeMulticodecKeyAlgorithm): ByteArray =
        algorithm.prefix()

    public fun expectedPublicKeyLength(algorithm: ReallyMeMulticodecKeyAlgorithm): Int? =
        algorithm.expectedPublicKeyLength

    public fun algorithmForCodecName(codecName: String): ReallyMeMulticodecKeyAlgorithm =
        ReallyMeMulticodecKeyAlgorithm.entries.firstOrNull { algorithm -> algorithm.codecName == codecName }
            ?: throw ReallyMeCryptoException.UnsupportedAlgorithm()

    internal fun lookupPublicKeyPrefix(bytes: ByteArray): ReallyMeMulticodecKeyAlgorithm? =
        ReallyMeMulticodecKeyAlgorithm.entries.firstOrNull { algorithm ->
            val prefix = algorithm.prefix()
            bytes.size >= prefix.size && bytes.copyOfRange(0, prefix.size).contentEquals(prefix)
        }
}
