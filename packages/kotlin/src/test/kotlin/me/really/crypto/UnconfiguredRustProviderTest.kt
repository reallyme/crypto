// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class UnconfiguredRustProviderTest {
    @Test
    fun unconfiguredRustRoutesReturnUnsupportedAlgorithm() {
        val key = ByteArray(ReallyMeRustAead.KEY_LENGTH)
        val nonce = ByteArray(ReallyMeRustAead.AES_GCM_SIV_NONCE_LENGTH)
        val empty = ByteArray(0)
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCrypto.seal(ReallyMeAeadAlgorithm.AES_256_GCM_SIV, key, nonce, empty, empty)
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCrypto.open(
                ReallyMeAeadAlgorithm.AES_256_GCM_SIV,
                key,
                nonce,
                empty,
                ByteArray(ReallyMeRustAead.TAG_LENGTH),
            )
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCrypto.processOperationResponse(empty)
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCrypto.processOperationResponseJson("{}".encodeToByteArray())
        }
        assertEquals(
            32,
            ReallyMeCrypto.hash(ReallyMeHashAlgorithm.SHA2_256, empty).size,
        )
    }
}
