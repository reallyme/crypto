// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.MessageDigest
import org.bouncycastle.crypto.digests.SHA3Digest

/**
 * Small JVM-native digest surface used by package tests and as the first
 * package API slice while algorithm wrappers are added one at a time.
 * Mirrors the Swift package's `ReallyMeDigest`.
 */
public object ReallyMeDigest {
    public fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    public fun sha384(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-384").digest(bytes)

    public fun sha512(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-512").digest(bytes)

    public fun sha3_224(bytes: ByteArray): ByteArray = sha3(bytes, bitLength = 224, outputLength = 28)

    public fun sha3_256(bytes: ByteArray): ByteArray = sha3(bytes, bitLength = 256, outputLength = 32)

    public fun sha3_384(bytes: ByteArray): ByteArray = sha3(bytes, bitLength = 384, outputLength = 48)

    public fun sha3_512(bytes: ByteArray): ByteArray = sha3(bytes, bitLength = 512, outputLength = 64)

    private fun sha3(bytes: ByteArray, bitLength: Int, outputLength: Int): ByteArray {
        val digest = SHA3Digest(bitLength)
        digest.update(bytes, 0, bytes.size)
        val out = ByteArray(outputLength)
        digest.doFinal(out, 0)
        return out
    }
}
