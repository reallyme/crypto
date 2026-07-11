// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

public object ReallyMeHmac {
    public const val MAX_KEY_LENGTH: Int = 4096
    public const val SHA256_TAG_LENGTH: Int = 32
    public const val SHA512_TAG_LENGTH: Int = 64

    public fun authenticateSha256(key: ByteArray, message: ByteArray): ByteArray =
        authenticate(ProviderAlgorithm.HMAC_SHA256, key, message)

    public fun authenticateSha512(key: ByteArray, message: ByteArray): ByteArray =
        authenticate(ProviderAlgorithm.HMAC_SHA512, key, message)

    public fun verifySha256(tag: ByteArray, key: ByteArray, message: ByteArray): Boolean {
        if (tag.size != SHA256_TAG_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return constantTimeEquals(tag, authenticateSha256(key, message))
    }

    public fun verifySha512(tag: ByteArray, key: ByteArray, message: ByteArray): Boolean {
        if (tag.size != SHA512_TAG_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return constantTimeEquals(tag, authenticateSha512(key, message))
    }

    private fun authenticate(
        algorithm: ProviderAlgorithm,
        key: ByteArray,
        message: ByteArray,
    ): ByteArray {
        validateKey(key)
        val mac = Mac.getInstance(algorithm.jceName)
        mac.init(SecretKeySpec(key, algorithm.jceName))
        return mac.doFinal(message)
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

    private enum class ProviderAlgorithm(val jceName: String) {
        HMAC_SHA256("HmacSHA256"),
        HMAC_SHA512("HmacSHA512"),
    }
}
