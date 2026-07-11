// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

private const val MULTIBASE_BASE58_BTC_PREFIX = 'z'
private const val MIN_MULTICODEC_PREFIX_LENGTH = 2

public class ReallyMeParsedMultikey(
    public val algorithm: ReallyMeMulticodecKeyAlgorithm,
    public val algorithmName: String,
    public val publicKey: ByteArray,
    public val expectedPublicKeyLength: Int?,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeParsedMultikey &&
            algorithm == other.algorithm &&
            algorithmName == other.algorithmName &&
            publicKey.contentEquals(other.publicKey) &&
            expectedPublicKeyLength == other.expectedPublicKeyLength

    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        result = 31 * result + algorithmName.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + (expectedPublicKeyLength ?: 0)
        return result
    }
}

public object ReallyMeMultikey {
    public fun encode(
        algorithm: ReallyMeMulticodecKeyAlgorithm,
        publicKey: ByteArray,
    ): String {
        validateKeyLength(algorithm, publicKey)

        val prefix = algorithm.prefix()
        if (publicKey.size > Int.MAX_VALUE - prefix.size) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        val payload = ByteArray(prefix.size + publicKey.size)
        prefix.copyInto(payload)
        publicKey.copyInto(payload, destinationOffset = prefix.size)

        return MULTIBASE_BASE58_BTC_PREFIX.toString() + ReallyMeBase58Btc.encode(payload)
    }

    public fun parse(multikey: String): ReallyMeParsedMultikey {
        if (multikey.isEmpty() || multikey.first() != MULTIBASE_BASE58_BTC_PREFIX) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        val payload = ReallyMeBase58Btc.decode(multikey.drop(1))
        if (payload.size < MIN_MULTICODEC_PREFIX_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        val algorithm = ReallyMeMulticodec.lookupPublicKeyPrefix(payload)
            ?: throw ReallyMeCryptoException.UnsupportedAlgorithm()
        val prefixLength = algorithm.prefix().size
        val publicKey = payload.copyOfRange(prefixLength, payload.size)
        validateKeyLength(algorithm, publicKey)

        return ReallyMeParsedMultikey(
            algorithm = algorithm,
            algorithmName = algorithm.algorithmName,
            publicKey = publicKey,
            expectedPublicKeyLength = algorithm.expectedPublicKeyLength,
        )
    }

    private fun validateKeyLength(
        algorithm: ReallyMeMulticodecKeyAlgorithm,
        publicKey: ByteArray,
    ) {
        val expectedLength = algorithm.expectedPublicKeyLength
        if (expectedLength != null) {
            if (publicKey.size != expectedLength) {
                throw ReallyMeCryptoException.InvalidInput()
            }
            return
        }

        if (publicKey.isEmpty()) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }
}
