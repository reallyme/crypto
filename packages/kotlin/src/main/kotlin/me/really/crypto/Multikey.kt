// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import me.really.codec.ReallyMeCodec
import me.really.codec.ReallyMeCodecException

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
    ): String = codecOperation {
        ReallyMeCodec.multikeyEncode(algorithm.codecName, publicKey)
    }

    public fun parse(multikey: String): ReallyMeParsedMultikey {
        val parsed = codecOperation {
            ReallyMeCodec.multikeyParse(multikey)
        }
        val algorithm = try {
            ReallyMeMulticodec.algorithmForCodecName(parsed.codecName)
        } catch (_: ReallyMeCryptoException.UnsupportedAlgorithm) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val expectedPublicKeyLength = parsed.expectedPublicKeyLength?.let { length ->
            if (length < 0 || length > Int.MAX_VALUE.toLong()) {
                throw ReallyMeCryptoException.ProviderFailure()
            }
            // The explicit range check above makes the SDK-width conversion
            // deterministic and prevents a future codec value from wrapping.
            length.toInt()
        }

        return ReallyMeParsedMultikey(
            algorithm = algorithm,
            algorithmName = parsed.algorithmName,
            publicKey = parsed.publicKey(),
            expectedPublicKeyLength = expectedPublicKeyLength,
        )
    }

    private inline fun <T> codecOperation(operation: () -> T): T = try {
        operation()
    } catch (_: ReallyMeCodecException.InvalidInput) {
        throw ReallyMeCryptoException.InvalidInput()
    } catch (_: ReallyMeCodecException.ProviderFailure) {
        throw ReallyMeCryptoException.ProviderFailure()
    }
}
