// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import java.util.jar.JarFile
import me.really.crypto.proto.ReallyMeCryptoProtoAdapters

class RustProtocolRoutingTest : ReallyMeCryptoTestSupport() {
    @Test
    fun productionApiAndJarContainNoCallerSeededEncapsulation() {
        for (owner in listOf(
            ReallyMeCrypto::class.java,
            ReallyMeMlKem::class.java,
            ReallyMeXWing::class.java,
            ReallyMeHpke::class.java,
            ReallyMeRustProtocols::class.java,
        )) {
            assertFalse(owner.declaredMethods.any {
                it.name.contains("Deterministic") || it.name.contains("ForTest")
            })
        }
        val path = assertNotNull(System.getProperty("reallyme.crypto.productionJar"))
        JarFile(path).use { jar ->
            assertFalse(jar.entries().asSequence().any {
                it.name.startsWith("me/really/crypto/ReallyMeProtocolConformance")
            })
        }
    }

    @BeforeTest
    fun loadRustProvider() {
        ReallyMeRustNativeProvider.loadBundledLibrary()
    }

    @Test
    fun pairTransportValidatesLengthsAndWipesItsOwnedBuffer() {
        val bytes = byteArrayOf(1, 2, 3, 4)
        val (first, second) = ReallyMeRustProtocols.decodePair(bytes, 2, 2)
        assertContentEquals(byteArrayOf(1, 2), first)
        assertContentEquals(byteArrayOf(3, 4), second)
        assertContentEquals(ByteArray(4), bytes)
        for ((firstLength, secondLength) in listOf(2 to 3, -1 to 5, Int.MAX_VALUE to 1)) {
            val malformed = byteArrayOf(1, 2, 3, 4)
            assertFailsWith<ReallyMeCryptoException.ProviderFailure> {
                ReallyMeRustProtocols.decodePair(malformed, firstLength, secondLength)
            }
            assertContentEquals(ByteArray(4), malformed)
        }
    }

    @Test
    fun nativeBoundaryRejectsUnknownIdentifiersNullAndOversizedInputs() {
        val encapsulate = ReallyMeRustProtocols::class.java.getDeclaredMethod(
            "encapsulateNative", Int::class.javaPrimitiveType, ByteArray::class.java,
        ).also { it.isAccessible = true }
        val algorithm = ReallyMeCryptoProtoAdapters.toProto(ReallyMeKemAlgorithm.X_WING_768).number
        for (unknown in listOf(0, -1, Int.MAX_VALUE)) {
            val result = encapsulate.invoke(null, unknown, ByteArray(0)) as? ByteArray
            assertEquals(ReallyMeNativeStatus.UNSUPPORTED_ALGORITHM, decodeRustNativeResult(result).status)
        }
        for (input in listOf(null, ByteArray(1_048_577))) {
            val result = encapsulate.invoke(null, algorithm, input) as? ByteArray
            assertEquals(ReallyMeNativeStatus.INVALID_INPUT, decodeRustNativeResult(result).status)
        }
    }

    @Test
    fun maximumHpkePlaintextRoundTripsAndOversizedPlaintextFailsClosed() {
        val suite = ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305
        val publicKey = vectorCaseField("hpke.json", "x25519_sha256_chacha20poly1305", "recipient_public_key")
        val secretKey = vectorCaseField("hpke.json", "x25519_sha256_chacha20poly1305", "recipient_secret_key")
        val plaintext = ByteArray(MAX_PROTOBUF_REQUEST_BYTES)
        try {
            val sealed = ReallyMeHpke.seal(suite, publicKey, ByteArray(0), ByteArray(0), plaintext)
            val opened = ReallyMeHpke.open(suite, secretKey, sealed.encapsulatedKey, ByteArray(0), ByteArray(0), sealed.ciphertext)
            try {
                assertContentEquals(plaintext, opened)
            } finally {
                opened.fill(0)
            }
            assertFailsWith<ReallyMeCryptoException.InvalidInput> {
                ReallyMeHpke.seal(suite, publicKey, ByteArray(0), ByteArray(0), ByteArray(MAX_PROTOBUF_REQUEST_BYTES + 1))
            }
        } finally {
            plaintext.fill(0)
            secretKey.fill(0)
        }
    }

    @Test
    fun productionProviderOmitsDeterministicConformanceEntryPoints() {
        assertTrue(System.getenv("REALLYME_CRYPTO_FFI_LIBRARY_PATH").isNullOrEmpty())
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeProtocolConformance.encapsulate(
                ReallyMeKemAlgorithm.X_WING_768,
                vectorCaseField("x_wing.json", "x_wing_768", "public_key"),
                ByteArray(ReallyMeXWing.ENCAPSULATION_SEED_LENGTH),
            )
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeProtocolConformance.seal(
                ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
                vectorCaseField("hpke.json", "x25519_sha256_chacha20poly1305", "recipient_public_key"),
                ByteArray(32), ByteArray(0), ByteArray(0), ByteArray(0),
            )
        }
    }

    @Test
    fun failedNativeOperationDoesNotFallBackToAnotherProvider() {
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            ReallyMeHpke.seal(
                ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
                ByteArray(32), ByteArray(0), ByteArray(0), ByteArray(0),
            )
        }
    }
}
