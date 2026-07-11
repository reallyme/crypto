// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.math.BigInteger

private const val BASE58_RADIX = 58
private const val BASE58_LEADER = '1'
private const val BASE58_INVALID_INDEX = -1
private const val ASCII_TABLE_SIZE = 128

private val BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
private val BASE58_INDEXES = IntArray(ASCII_TABLE_SIZE) { BASE58_INVALID_INDEX }.also { indexes ->
    BASE58_ALPHABET.forEachIndexed { index, char ->
        indexes[char.code] = index
    }
}

internal object ReallyMeBase58Btc {
    private val radix = BigInteger.valueOf(BASE58_RADIX.toLong())

    fun encode(bytes: ByteArray): String {
        if (bytes.isEmpty()) {
            return ""
        }

        val leadingZeros = bytes.takeWhile { byte -> byte == 0.toByte() }.count()
        var value = BigInteger(1, bytes)
        val encoded = StringBuilder()

        while (value > BigInteger.ZERO) {
            val quotientAndRemainder = value.divideAndRemainder(radix)
            value = quotientAndRemainder[0]
            val digit = quotientAndRemainder[1].toInt()
            encoded.append(BASE58_ALPHABET[digit])
        }

        repeat(leadingZeros) {
            encoded.append(BASE58_LEADER)
        }

        return encoded.reverse().toString()
    }

    fun decode(encoded: String): ByteArray {
        if (encoded.isEmpty()) {
            return ByteArray(0)
        }

        var value = BigInteger.ZERO
        for (char in encoded) {
            if (char.code >= ASCII_TABLE_SIZE) {
                throw ReallyMeCryptoException.InvalidInput()
            }
            val digit = BASE58_INDEXES[char.code]
            if (digit == BASE58_INVALID_INDEX) {
                throw ReallyMeCryptoException.InvalidInput()
            }
            value = value.multiply(radix).add(BigInteger.valueOf(digit.toLong()))
        }

        val leadingZeros = encoded.takeWhile { char -> char == BASE58_LEADER }.count()
        val magnitude = unsignedMagnitude(value)
        val decoded = ByteArray(leadingZeros + magnitude.size)
        magnitude.copyInto(decoded, destinationOffset = leadingZeros)
        return decoded
    }

    private fun unsignedMagnitude(value: BigInteger): ByteArray {
        val magnitude = value.toByteArray()
        if (magnitude.size > 1 && magnitude[0] == 0.toByte()) {
            return magnitude.copyOfRange(1, magnitude.size)
        }
        if (value == BigInteger.ZERO) {
            return ByteArray(0)
        }
        return magnitude
    }
}
