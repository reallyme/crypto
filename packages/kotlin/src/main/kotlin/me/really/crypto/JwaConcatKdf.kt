// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * JWA ECDH-ES Concat KDF over SHA-256.
 *
 * JOSE parsing and header policy stay outside this primitive; callers pass
 * already-decoded `AlgorithmID`, `PartyUInfo`, and `PartyVInfo` values.
 */
public object ReallyMeJwaConcatKdf {
    public const val SHA256_DIGEST_LENGTH: Int = 32
    public const val MAX_SHARED_SECRET_LENGTH: Int = 4096
    public const val MAX_INFO_LENGTH: Int = 4096
    public const val MIN_OUTPUT_LENGTH: Int = 1
    public const val MAX_OUTPUT_LENGTH: Int = 4096

    public fun deriveSha256(
        sharedSecret: ByteArray,
        algorithmId: ByteArray,
        partyUInfo: ByteArray,
        partyVInfo: ByteArray,
        outputLength: Int,
    ): ByteArray {
        validate(sharedSecret, algorithmId, partyUInfo, partyVInfo, outputLength)
        val outputBits = checkedOutputBits(outputLength)
        val otherInfo = buildOtherInfo(algorithmId, partyUInfo, partyVInfo, outputBits)
        val reps = (outputLength + SHA256_DIGEST_LENGTH - 1) / SHA256_DIGEST_LENGTH
        val derived = ByteArray(reps * SHA256_DIGEST_LENGTH)

        for (counter in 1..reps) {
            val digest = sha256Digest()
            val counterBytes = uint32be(counter)
            digest.update(counterBytes)
            digest.update(sharedSecret)
            digest.update(otherInfo)
            val block = digest.digest()
            block.copyInto(derived, destinationOffset = (counter - 1) * SHA256_DIGEST_LENGTH)
            block.fill(0)
            counterBytes.fill(0)
        }

        val output = derived.copyOf(outputLength)
        derived.fill(0)
        otherInfo.fill(0)
        return output
    }

    private fun validate(
        sharedSecret: ByteArray,
        algorithmId: ByteArray,
        partyUInfo: ByteArray,
        partyVInfo: ByteArray,
        outputLength: Int,
    ) {
        if (sharedSecret.isEmpty() ||
            sharedSecret.size > MAX_SHARED_SECRET_LENGTH ||
            algorithmId.isEmpty() ||
            algorithmId.size > MAX_INFO_LENGTH ||
            partyUInfo.size > MAX_INFO_LENGTH ||
            partyVInfo.size > MAX_INFO_LENGTH ||
            outputLength !in MIN_OUTPUT_LENGTH..MAX_OUTPUT_LENGTH
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun checkedOutputBits(outputLength: Int): Int {
        val outputBits = outputLength.toLong() * Byte.SIZE_BITS.toLong()
        if (outputBits > Int.MAX_VALUE.toLong()) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return outputBits.toInt()
    }

    private fun buildOtherInfo(
        algorithmId: ByteArray,
        partyUInfo: ByteArray,
        partyVInfo: ByteArray,
        outputBits: Int,
    ): ByteArray {
        val totalLength =
            lengthPrefixedCapacity(algorithmId) +
                lengthPrefixedCapacity(partyUInfo) +
                lengthPrefixedCapacity(partyVInfo) +
                UINT32_LENGTH
        val output = ByteArray(totalLength)
        var offset = appendLengthPrefixed(output, 0, algorithmId)
        offset = appendLengthPrefixed(output, offset, partyUInfo)
        offset = appendLengthPrefixed(output, offset, partyVInfo)
        uint32be(outputBits).copyInto(output, destinationOffset = offset)
        return output
    }

    private fun lengthPrefixedCapacity(bytes: ByteArray): Int = UINT32_LENGTH + bytes.size

    private fun appendLengthPrefixed(output: ByteArray, offset: Int, bytes: ByteArray): Int {
        uint32be(bytes.size).copyInto(output, destinationOffset = offset)
        val valueOffset = offset + UINT32_LENGTH
        bytes.copyInto(output, destinationOffset = valueOffset)
        return valueOffset + bytes.size
    }

    private fun uint32be(value: Int): ByteArray =
        byteArrayOf(
            ((value ushr 24) and 0xff).toByte(),
            ((value ushr 16) and 0xff).toByte(),
            ((value ushr 8) and 0xff).toByte(),
            (value and 0xff).toByte(),
        )

    private fun sha256Digest(): MessageDigest =
        try {
            MessageDigest.getInstance("SHA-256")
        } catch (_: NoSuchAlgorithmException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }

    private const val UINT32_LENGTH = 4
}
