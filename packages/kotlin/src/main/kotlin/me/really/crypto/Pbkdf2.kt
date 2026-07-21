// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter

public object ReallyMePbkdf2 {
    public const val MIN_INPUT_LENGTH: Int = 1
    public const val MAX_INPUT_LENGTH: Int = 4096
    /** Minimum work factor accepted by public PBKDF2 derivation routes. */
    public const val MIN_ITERATIONS: UInt = 100_000u

    /** Maximum work factor accepted before CPU-expensive provider dispatch. */
    public const val MAX_ITERATIONS: UInt = 10_000_000u
    public const val MIN_OUTPUT_LENGTH: Int = 1
    public const val MAX_OUTPUT_LENGTH: Int = 4096

    public fun deriveHmacSha256(
        password: ByteArray,
        salt: ByteArray,
        iterations: UInt,
        outputLength: Int,
    ): ByteArray =
        derive(ProviderAlgorithm.PBKDF2_HMAC_SHA256, password, salt, iterations, outputLength)

    public fun deriveHmacSha512(
        password: ByteArray,
        salt: ByteArray,
        iterations: UInt,
        outputLength: Int,
    ): ByteArray =
        derive(ProviderAlgorithm.PBKDF2_HMAC_SHA512, password, salt, iterations, outputLength)

    private fun derive(
        algorithm: ProviderAlgorithm,
        password: ByteArray,
        salt: ByteArray,
        iterations: UInt,
        outputLength: Int,
    ): ByteArray {
        val providerIterations = validate(password, salt, iterations, outputLength)
        val generator = when (algorithm) {
            ProviderAlgorithm.PBKDF2_HMAC_SHA256 -> PKCS5S2ParametersGenerator(SHA256Digest())
            ProviderAlgorithm.PBKDF2_HMAC_SHA512 -> PKCS5S2ParametersGenerator(SHA512Digest())
        }
        generator.init(password, salt, providerIterations)

        val bitLength = outputLength.checkedMultiply(Byte.SIZE_BITS)
        val parameters = generator.generateDerivedParameters(bitLength)
        if (parameters !is KeyParameter) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
        val derived = parameters.key
        return try {
            derived.copyOf()
        } finally {
            derived.fill(0)
        }
    }

    private fun validate(
        password: ByteArray,
        salt: ByteArray,
        iterations: UInt,
        outputLength: Int,
    ): Int {
        if (password.size !in MIN_INPUT_LENGTH..MAX_INPUT_LENGTH ||
            salt.size !in MIN_INPUT_LENGTH..MAX_INPUT_LENGTH ||
            outputLength !in MIN_OUTPUT_LENGTH..MAX_OUTPUT_LENGTH
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return checkedIterationCount(iterations)
    }

    internal fun checkedIterationCount(iterations: UInt): Int {
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        // The policy range also proves this conversion cannot wrap negative.
        return iterations.toInt()
    }

    private fun Int.checkedMultiply(multiplier: Int): Int {
        val result = this.toLong() * multiplier.toLong()
        if (result > Int.MAX_VALUE) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return result.toInt()
    }

    private enum class ProviderAlgorithm {
        PBKDF2_HMAC_SHA256,
        PBKDF2_HMAC_SHA512,
    }
}
