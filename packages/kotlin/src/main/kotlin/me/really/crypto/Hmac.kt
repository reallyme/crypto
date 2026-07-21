// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.GeneralSecurityException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

public object ReallyMeHmac {
    public const val MAX_KEY_LENGTH: Int = 4096
    public const val SHA256_TAG_LENGTH: Int = 32
    public const val SHA384_TAG_LENGTH: Int = 48
    public const val SHA512_TAG_LENGTH: Int = 64

    public fun authenticateSha256(key: ByteArray, message: ByteArray): ByteArray =
        authenticate(ProviderAlgorithm.HMAC_SHA256, key, message)

    public fun authenticateSha384(key: ByteArray, message: ByteArray): ByteArray =
        authenticate(ProviderAlgorithm.HMAC_SHA384, key, message)

    public fun authenticateSha512(key: ByteArray, message: ByteArray): ByteArray =
        authenticate(ProviderAlgorithm.HMAC_SHA512, key, message)

    public fun verifySha256(tag: ByteArray, key: ByteArray, message: ByteArray): Boolean {
        if (tag.size != SHA256_TAG_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return verifyAndClearExpectedTag(tag, authenticateSha256(key, message))
    }

    public fun verifySha384(tag: ByteArray, key: ByteArray, message: ByteArray): Boolean {
        if (tag.size != SHA384_TAG_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return verifyAndClearExpectedTag(tag, authenticateSha384(key, message))
    }

    public fun verifySha512(tag: ByteArray, key: ByteArray, message: ByteArray): Boolean {
        if (tag.size != SHA512_TAG_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return verifyAndClearExpectedTag(tag, authenticateSha512(key, message))
    }

    private fun authenticate(
        algorithm: ProviderAlgorithm,
        key: ByteArray,
        message: ByteArray,
    ): ByteArray {
        validateKey(key)
        return try {
            val mac = Mac.getInstance(algorithm.jceName)
            mac.init(SecretKeySpec(key, algorithm.jceName))
            mac.doFinal(message)
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun validateKey(key: ByteArray) {
        if (key.isEmpty() || key.size > MAX_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean {
        if (left.size != right.size) {
            return false
        }
        var difference = 0
        for (index in left.indices) {
            difference = difference or (left[index].toInt() xor right[index].toInt())
        }
        return difference == 0
    }

    private fun verifyAndClearExpectedTag(tag: ByteArray, expectedTag: ByteArray): Boolean =
        try {
            constantTimeEquals(tag, expectedTag)
        } finally {
            // JCE returns a new managed array. Clear it immediately so verification
            // does not retain key-derived authentication material until a GC cycle.
            expectedTag.fill(0)
        }

    private enum class ProviderAlgorithm(val jceName: String) {
        HMAC_SHA256("HmacSHA256"),
        HMAC_SHA384("HmacSHA384"),
        HMAC_SHA512("HmacSHA512"),
    }
}
