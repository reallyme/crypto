// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

private const val X25519_PUBLIC_KEY_LENGTH: Int = 32
private const val X25519_FIELD_PRIME_LOW_BYTE: Int = 0xed
private const val X25519_FIELD_PRIME_HIGH_BYTE: Int = 0x7f

/** Envelopes reject field-element aliases even though RFC 7748 agreement accepts them. */
internal fun isCanonicalX25519Identity(publicKey: ByteArray): Boolean {
    if (publicKey.size != X25519_PUBLIC_KEY_LENGTH) {
        return false
    }
    val highByte = publicKey[31].toInt() and 0xff
    if (highByte > X25519_FIELD_PRIME_HIGH_BYTE) {
        return false
    }
    return highByte != X25519_FIELD_PRIME_HIGH_BYTE ||
        (1 until 31).any { index -> (publicKey[index].toInt() and 0xff) != 0xff } ||
        (publicKey[0].toInt() and 0xff) < X25519_FIELD_PRIME_LOW_BYTE
}
