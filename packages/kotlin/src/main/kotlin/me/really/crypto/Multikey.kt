// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import com.google.protobuf.InvalidProtocolBufferException
import me.really.codec.ReallyMeCodec
import me.really.codec.ReallyMeCodecException
import me.really.codec.v1.CodecMultikeyParseResult

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
            try {
                CodecMultikeyParseResult.parseFrom(ReallyMeCodec.multikeyParseProto(multikey))
            } catch (_: InvalidProtocolBufferException) {
                throw ReallyMeCryptoException.ProviderFailure()
            }
        }
        val algorithm = try {
            ReallyMeMulticodec.algorithmForCodecName(parsed.codecName)
        } catch (_: ReallyMeCryptoException.UnsupportedAlgorithm) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val expectedPublicKeyLength = if (parsed.variablePublicKeyLength) {
            null
        } else {
            parsed.expectedPublicKeyLength
        }

        return ReallyMeParsedMultikey(
            algorithm = algorithm,
            algorithmName = parsed.algorithmName,
            publicKey = parsed.publicKey.toByteArray(),
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
