// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.math.BigInteger
import java.security.SecureRandom
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.FixedPointCombMultiplier

/**
 * P-521 ECDH backed by BouncyCastle.
 *
 * Public keys at the SDK boundary are compressed SEC1. The primitive returns
 * the raw 66-byte ECDH x-coordinate; protocols must apply a labelled KDF that
 * binds algorithm and party context before using it as key material.
 */
public object ReallyMeP521Ecdh {
    public const val SECRET_KEY_LENGTH: Int = 66
    public const val COMPRESSED_PUBLIC_KEY_LENGTH: Int = 67
    public const val SHARED_SECRET_LENGTH: Int = 66

    private val domain: ECDomainParameters =
        ECDomainParameters(SECNamedCurves.getByName("secp521r1"))

    public fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val random = SecureRandom()
        val secretKey = ByteArray(SECRET_KEY_LENGTH)
        repeat(1024) {
            random.nextBytes(secretKey)
            val scalar = BigInteger(1, secretKey)
            if (scalar.signum() > 0 && scalar < domain.n) {
                return Pair(derivePublicKey(secretKey), secretKey.copyOf())
            }
        }
        throw ReallyMeCryptoException.ProviderFailure()
    }

    public fun deriveKeyPair(secretKey: ByteArray): Pair<ByteArray, ByteArray> =
        Pair(derivePublicKey(secretKey), secretKey.copyOf())

    public fun derivePublicKey(secretKey: ByteArray): ByteArray {
        val scalar = validatedScalar(secretKey)
        return FixedPointCombMultiplier().multiply(domain.g, scalar).normalize().getEncoded(true)
    }

    public fun deriveSharedSecret(publicKey: ByteArray, secretKey: ByteArray): ByteArray {
        if (publicKey.size != COMPRESSED_PUBLIC_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val scalar = validatedScalar(secretKey)
        val point = try {
            domain.curve.decodePoint(publicKey).multiply(scalar).normalize()
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        if (point.isInfinity) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return encodeFixed(point.affineXCoord.toBigInteger())
    }

    private fun validatedScalar(secretKey: ByteArray): BigInteger {
        if (secretKey.size != SECRET_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val scalar = BigInteger(1, secretKey)
        if (scalar.signum() <= 0 || scalar >= domain.n) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return scalar
    }

    private fun encodeFixed(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        val out = ByteArray(SHARED_SECRET_LENGTH)
        val start = if (bytes.size > SHARED_SECRET_LENGTH) bytes.size - SHARED_SECRET_LENGTH else 0
        val length = bytes.size - start
        System.arraycopy(bytes, start, out, SHARED_SECRET_LENGTH - length, length)
        bytes.fill(0)
        return out
    }
}
