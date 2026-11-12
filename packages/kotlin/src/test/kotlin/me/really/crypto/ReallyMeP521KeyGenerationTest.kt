// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import java.security.ProviderException
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.bouncycastle.asn1.sec.SECNamedCurves

class ReallyMeP521KeyGenerationTest {
    private val generators: List<(SecureRandom) -> Pair<ByteArray, ByteArray>> = listOf(
        { random -> ReallyMeP521Ecdh.generateKeyPair(random) },
        { random -> ReallyMeP521Ecdsa.generateKeyPair(random) },
    )

    @Test
    fun masksUnusedBitsBeforeRejectionAndClearsAcceptedCandidate() {
        val entropy = ByteArray(ReallyMeP521Ecdh.SECRET_KEY_LENGTH) { 1 }
        entropy[0] = 0xff.toByte()
        val expected = entropy.copyOf().also { it[0] = 1 }
        for (generate in generators) {
            val random = RecordingRandom(listOf(entropy))
            val (publicKey, secretKey) = generate(random)
            try {
                assertEquals(1, random.draws)
                assertContentEquals(expected, secretKey)
                assertContentEquals(ReallyMeP521Ecdh.derivePublicKey(expected), publicKey)
                assertTrue(random.candidate?.all { it == 0.toByte() } == true)
            } finally {
                secretKey.fill(0)
            }
        }
        entropy.fill(0)
        expected.fill(0)
    }

    @Test
    fun rejectsZeroOrderAndAboveOrderAfterMasking() {
        val width = ReallyMeP521Ecdh.SECRET_KEY_LENGTH
        val zeroAfterMasking = ByteArray(width).also { it[0] = 0xfe.toByte() }
        val order = SECNamedCurves.getByName("secp521r1").n.toByteArray()
        assertEquals(width, order.size)
        val aboveOrder = order.copyOf().also { it[it.lastIndex] = (it.last().toInt() + 1).toByte() }
        val valid = ByteArray(width).also { it[it.lastIndex] = 1 }
        for (generate in generators) {
            val random = RecordingRandom(listOf(zeroAfterMasking, order, aboveOrder, valid))
            val (_, secretKey) = generate(random)
            try {
                assertEquals(4, random.draws)
                assertContentEquals(valid, secretKey)
                assertTrue(random.candidate?.all { it == 0.toByte() } == true)
            } finally {
                secretKey.fill(0)
            }
        }
    }

    @Test
    fun exhaustedSamplingHasTypedFailureAndClearsCandidate() {
        val invalid = ByteArray(ReallyMeP521Ecdh.SECRET_KEY_LENGTH) { 0xff.toByte() }
        for (generate in generators) {
            val random = RecordingRandom(listOf(invalid))
            assertFailsWith<ReallyMeCryptoException.ProviderFailure> { generate(random) }
            assertEquals(1_024, random.draws)
            assertTrue(random.candidate?.all { it == 0.toByte() } == true)
        }
    }

    @Test
    fun partialEntropyFailureHasTypedFailureAndClearsCandidate() {
        val partial = ByteArray(ReallyMeP521Ecdh.SECRET_KEY_LENGTH) { 0x7f }
        for (generate in generators) {
            val random = RecordingRandom(listOf(partial), failAfterWrite = true)
            assertFailsWith<ReallyMeCryptoException.ProviderFailure> { generate(random) }
            assertEquals(1, random.draws)
            assertTrue(random.candidate?.all { it == 0.toByte() } == true)
        }
    }

    @Test
    fun candidateIsClearedWhenPreparationValidationOrResultConstructionFails() {
        for (failureStage in 0..2) {
            val random = RecordingRandom(listOf(byteArrayOf(1)))
            assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                withRandomSecretCandidate(
                    length = 1,
                    random = random,
                    prepareCandidate = {
                        if (failureStage == 0) throw ReallyMeCryptoException.InvalidInput()
                    },
                    isValid = {
                        if (failureStage == 1) throw ReallyMeCryptoException.InvalidInput()
                        true
                    },
                    buildResult = {
                        throw ReallyMeCryptoException.InvalidInput()
                    },
                )
            }
            assertTrue(random.candidate?.all { it == 0.toByte() } == true)
        }
    }

    private class RecordingRandom(
        private val values: List<ByteArray>,
        private val failAfterWrite: Boolean = false,
    ) : SecureRandom() {
        var draws: Int = 0
            private set
        var candidate: ByteArray? = null
            private set

        override fun nextBytes(bytes: ByteArray) {
            values[minOf(draws, values.lastIndex)].copyInto(bytes)
            draws += 1
            candidate = bytes
            if (failAfterWrite) throw ProviderException()
        }
    }
}
