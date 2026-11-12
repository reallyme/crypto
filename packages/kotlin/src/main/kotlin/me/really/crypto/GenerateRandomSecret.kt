// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import java.security.ProviderException
import java.security.SecureRandom

private const val MAX_SECRET_KEY_GENERATION_ATTEMPTS: Int = 1_024

/**
 * Rejection-samples a secret and clears the internal candidate on every exit.
 *
 * [prepareCandidate] may mask unused representation bits before validation;
 * it must not reduce modulo an order, which would bias the distribution.
 * [buildResult] must copy any secret bytes that the caller needs to retain.
 * Keeping ownership of the sampling buffer here prevents a second accepted
 * scalar from remaining reachable until a later JVM garbage collection.
 */
internal fun <Result> withRandomSecretCandidate(
    length: Int,
    random: SecureRandom = SecureRandom(),
    prepareCandidate: (ByteArray) -> Unit = {},
    isValid: (ByteArray) -> Boolean,
    buildResult: (ByteArray) -> Result,
): Result {
    val candidate = ByteArray(length)
    try {
        repeat(MAX_SECRET_KEY_GENERATION_ATTEMPTS) {
            try {
                random.nextBytes(candidate)
            } catch (_: ProviderException) {
                throw ReallyMeCryptoException.ProviderFailure()
            }
            prepareCandidate(candidate)
            if (isValid(candidate)) {
                return buildResult(candidate)
            }
        }
        throw ReallyMeCryptoException.ProviderFailure()
    } finally {
        candidate.fill(0)
    }
}
