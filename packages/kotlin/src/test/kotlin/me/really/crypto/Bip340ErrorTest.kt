// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import kotlin.test.Test
import kotlin.test.assertFailsWith

class Bip340ErrorTest : ReallyMeCryptoTestSupport() {
    @Test
    fun sharedInvalidPublicKeysHaveTheSameErrorAsRust() {
        val signature = vectorField("bip340_schnorr.json", "signature")
        val message = vectorField("bip340_schnorr.json", "message")
        val publicKey = vectorField("bip340_schnorr.json", "public_key_xonly")
        ReallyMeBip340Schnorr.verify(signature, message, publicKey)
        for (field in listOf("invalid_off_curve_public_key_xonly", "invalid_out_of_range_public_key_xonly")) {
            val invalidKey = vectorField("bip340_schnorr.json", field)
            assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                ReallyMeBip340Schnorr.verify(signature, message, invalidKey)
            }
        }
        val tampered = signature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            ReallyMeBip340Schnorr.verify(tampered, message, publicKey)
        }
    }
}
