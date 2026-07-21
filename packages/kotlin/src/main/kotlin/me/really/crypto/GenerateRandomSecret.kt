// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.SecureRandom

private const val MAX_SECRET_KEY_GENERATION_ATTEMPTS: Int = 1_024

/**
 * Rejection-samples a secret and clears the internal candidate on every exit.
 *
 * [buildResult] must copy any secret bytes that the caller needs to retain.
 * Keeping ownership of the sampling buffer here prevents a second accepted
 * scalar from remaining reachable until a later JVM garbage collection.
 */
internal fun <Result> withRandomSecretCandidate(
    length: Int,
    random: SecureRandom = SecureRandom(),
    isValid: (ByteArray) -> Boolean,
    buildResult: (ByteArray) -> Result,
): Result {
    val candidate = ByteArray(length)
    try {
        repeat(MAX_SECRET_KEY_GENERATION_ATTEMPTS) {
            random.nextBytes(candidate)
            if (isValid(candidate)) {
                return buildResult(candidate)
            }
        }
        throw ReallyMeCryptoException.ProviderFailure()
    } finally {
        candidate.fill(0)
    }
}
