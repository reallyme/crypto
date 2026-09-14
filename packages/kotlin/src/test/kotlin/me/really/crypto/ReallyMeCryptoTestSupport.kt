// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.security.SecureRandom
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import me.really.crypto.proto.ReallyMeCryptoProtoAdapters
import me.really.crypto.proto.ReallyMeCryptoWireErrorBranch
import me.really.crypto.v1.CryptoErrorReason
import me.really.crypto.v1.CryptoOperationResponse
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.junit.jupiter.api.Assumptions.assumeTrue

internal const val MAX_PROTOBUF_REQUEST_BYTES: Int = 1_048_576
internal const val MAX_PROTO_JSON_REQUEST_BYTES: Int = 1_572_864

abstract class ReallyMeCryptoTestSupport {
    // Key agreement case from vectors/x25519.json — the same KAT every lane proves.
    protected val x25519SecretKey: ByteArray =
        bytes("13b40e434329c8395922a66d6fb8c50d3b35263f8e5c06cac624a86527d3b304")
    protected val x25519PublicKey: ByteArray =
        bytes("cbbec1ce67440087d03bfd8536ea3f7fa922cf529abc66578b62f3bf5ab26141")
    protected val x25519PeerSecretKey: ByteArray =
        bytes("73806939b0f9e8d2ae4c3d70a4b725933687d2858ca5d08960a9e25450ef50ae")
    protected val x25519PeerPublicKey: ByteArray =
        bytes("4444a8bf80ad7e56fc28dbc826d9f44fc49bd945f3ba2626138f791d7a55180b")
    protected val x25519SharedSecret: ByteArray =
        bytes("e00c4d62a8beeeedc0d7d0aca78e4c94395a063539a8204ce8fc11120e8dbc18")

    protected fun loadCryptoProviderForTestOrReturn(): String? {
        val libraryPath = System.getenv("REALLYME_CRYPTO_FFI_LIBRARY_PATH")
        if (libraryPath.isNullOrEmpty()) {
            return null
        }
        ReallyMeRustNativeProvider.loadLibrary(libraryPath)
        return libraryPath
    }

    protected fun nativeAeadMethod(name: String): java.lang.reflect.Method =
        ReallyMeRustAead::class.java.getDeclaredMethod(
            name,
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
        ).also { method -> method.isAccessible = true }

    protected fun assertRustAeadRoundTrip(
        algorithm: ReallyMeAeadAlgorithm,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
        ciphertext: ByteArray,
    ) {
        assertContentEquals(ciphertext, ReallyMeCrypto.seal(algorithm, key, nonce, aad, plaintext))
        assertContentEquals(plaintext, ReallyMeCrypto.open(algorithm, key, nonce, aad, ciphertext))

        val tampered = ciphertext.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
        assertFailsWith<ReallyMeCryptoException.AuthenticationFailed>(message = algorithm.algorithmName) {
            ReallyMeCrypto.open(algorithm, key, nonce, aad, tampered)
        }
    }

    protected fun assertNistEcdsaProvider(
        algorithm: ReallyMeSignatureAlgorithm,
        vectorFile: String,
        secretKeyLength: Int,
        publicKeyLength: Int,
        derivePublicKey: (ByteArray) -> ByteArray,
        sign: (ByteArray, ByteArray) -> ByteArray,
        verify: (ByteArray, ByteArray, ByteArray) -> Unit,
    ) {
        val secretKey = vectorField(vectorFile, "secret_key")
        val publicKey = vectorField(vectorFile, "public_key_compressed")
        val message = vectorField(vectorFile, "message")
        val signature = vectorField(vectorFile, "signature_der")

        assertContentEquals(publicKey, derivePublicKey(secretKey))
        assertContentEquals(publicKey, ReallyMeCrypto.deriveKeyPair(algorithm, secretKey).publicKey)
        assertContentEquals(signature, sign(message, secretKey))
        verify(signature, message, publicKey)

        val facadeSignature = ReallyMeCrypto.sign(algorithm, message, secretKey)
        assertContentEquals(signature, facadeSignature)
        ReallyMeCrypto.verify(algorithm, signature, message, publicKey)

        val tampered = signature.copyOf()
        tampered[tampered.lastIndex] = (tampered[tampered.lastIndex].toInt() xor 0x01).toByte()
        assertFailsWith<ReallyMeCryptoException.InvalidSignature> {
            verify(tampered, message, publicKey)
        }

        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            sign(message, byteArrayOf(0x01, 0x02))
        }
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            verify(ByteArray(7), message, publicKey)
        }
        val invalidKey = publicKey.copyOf()
        invalidKey[0] = 0x07
        assertFailsWith<ReallyMeCryptoException.InvalidInput> {
            verify(signature, message, invalidKey)
        }

        val generated = ReallyMeCrypto.generateKeyPair(algorithm)
        assertEquals(secretKeyLength, generated.secretKey.size)
        assertEquals(publicKeyLength, generated.publicKey.size)
        val generatedSignature = ReallyMeCrypto.sign(algorithm, message, generated.secretKey)
        ReallyMeCrypto.verify(algorithm, generatedSignature, message, generated.publicKey)
    }

    protected fun bytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { index ->
            hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }

    protected fun base64UrlBytes(encoded: String): ByteArray = Base64.getUrlDecoder().decode(encoded)

    protected fun base64UrlString(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    protected fun vectorField(vectorName: String, fieldName: String): ByteArray {
        return base64UrlBytes(vectorString(vectorName, fieldName))
    }

    protected fun vectorString(vectorName: String, fieldName: String): String {
        val vectorPath = Path.of("..", "..", "vectors", vectorName)
        val text = Files.readString(vectorPath)
        val match = Regex("\"$fieldName\"\\s*:\\s*\"([^\"]+)\"").find(text)
            ?: throw IllegalStateException("missing vector field")
        return match.groupValues[1]
    }

    protected fun vectorNumber(vectorName: String, fieldName: String): Int {
        val vectorPath = Path.of("..", "..", "vectors", vectorName)
        val text = Files.readString(vectorPath)
        val match = Regex("\"$fieldName\"\\s*:\\s*([0-9]+)").find(text)
            ?: throw IllegalStateException("missing vector field")
        return match.groupValues[1].toInt()
    }

    protected data class JwkVector(
        val alg: String,
        val publicKey: String,
        val publicKeyLength: Int,
        val jwkJcs: String,
        val multikey: String?,
        val multikeyStatus: String,
    )

    protected fun jwkVectors(): List<JwkVector> {
        val vectorPath = Path.of("..", "..", "vectors", "jwk.json")
        val text = Files.readString(vectorPath)
        return topLevelVectorObjects(text).map { entry ->
            JwkVector(
                alg = jsonStringField(entry, "alg"),
                publicKey = jsonStringField(entry, "public_key"),
                publicKeyLength = jsonNumberField(entry, "public_key_length"),
                jwkJcs = jsonStringField(entry, "jwk_jcs"),
                multikey = jsonOptionalStringField(entry, "multikey"),
                multikeyStatus = jsonStringField(entry, "multikey_status"),
            )
        }.toList()
    }

    protected fun topLevelVectorObjects(text: String): List<String> {
        val vectorsIndex = text.indexOf("\"vectors\"")
        if (vectorsIndex < 0) {
            throw IllegalStateException("missing jwk vectors array")
        }
        val arrayStart = text.indexOf('[', vectorsIndex)
        if (arrayStart < 0) {
            throw IllegalStateException("missing jwk vectors array")
        }

        val objects = mutableListOf<String>()
        var depth = 0
        var start = -1
        var inString = false
        var escaping = false
        var index = arrayStart + 1
        while (index < text.length) {
            val char = text[index]
            if (inString) {
                if (escaping) {
                    escaping = false
                } else if (char == '\\') {
                    escaping = true
                } else if (char == '"') {
                    inString = false
                }
            } else {
                when (char) {
                    '"' -> inString = true
                    '{' -> {
                        if (depth == 0) {
                            start = index
                        }
                        depth += 1
                    }
                    '}' -> {
                        depth -= 1
                        if (depth == 0 && start >= 0) {
                            objects.add(text.substring(start, index + 1))
                            start = -1
                        }
                    }
                    ']' -> if (depth == 0) {
                        return objects
                    }
                }
            }
            index += 1
        }
        throw IllegalStateException("unterminated jwk vectors array")
    }

    protected fun jsonStringField(text: String, fieldName: String): String {
        val fieldIndex = text.indexOf("\"$fieldName\"")
        if (fieldIndex < 0) {
            throw IllegalStateException("missing string field")
        }
        val colon = text.indexOf(':', fieldIndex)
        val firstQuote = text.indexOf('"', colon + 1)
        if (colon < 0 || firstQuote < 0) {
            throw IllegalStateException("missing string field")
        }
        val out = StringBuilder()
        var index = firstQuote + 1
        var escaping = false
        while (index < text.length) {
            val char = text[index]
            if (escaping) {
                out.append(
                    when (char) {
                        '"', '\\', '/' -> char
                        'b' -> '\b'
                        'f' -> '\u000C'
                        'n' -> '\n'
                        'r' -> '\r'
                        't' -> '\t'
                        else -> throw IllegalStateException("unsupported escape")
                    },
                )
                escaping = false
            } else if (char == '\\') {
                escaping = true
            } else if (char == '"') {
                return out.toString()
            } else {
                out.append(char)
            }
            index += 1
        }
        throw IllegalStateException("unterminated string field")
    }

    protected enum class YMutation {
        SAME_PARITY,
        OPPOSITE_PARITY,
    }

    protected fun mutatedEcJwkJson(jwkJcs: String, mutation: YMutation): String {
        val encodedY = jsonStringField(jwkJcs, "y")
        val y = base64UrlBytes(encodedY)
        when (mutation) {
            YMutation.SAME_PARITY -> y[0] = (y[0].toInt() xor 0x02).toByte()
            YMutation.OPPOSITE_PARITY -> y[31] = (y[31].toInt() xor 0x01).toByte()
        }
        return jwkJcs.replace(
            """"y":"$encodedY"""",
            """"y":"${base64UrlString(y)}"""",
        )
    }

    protected fun jsonOptionalStringField(text: String, fieldName: String): String? {
        val fieldIndex = text.indexOf("\"$fieldName\"")
        if (fieldIndex < 0) {
            throw IllegalStateException("missing optional string field")
        }
        val colon = text.indexOf(':', fieldIndex)
        if (colon < 0) {
            throw IllegalStateException("missing optional string field")
        }
        var index = colon + 1
        while (index < text.length && text[index].isWhitespace()) {
            index += 1
        }
        if (text.startsWith("null", index)) {
            return null
        }
        return jsonStringField(text, fieldName)
    }

    protected fun jsonNumberField(text: String, fieldName: String): Int {
        val fieldIndex = text.indexOf("\"$fieldName\"")
        if (fieldIndex < 0) {
            throw IllegalStateException("missing number field")
        }
        val colon = text.indexOf(':', fieldIndex)
        if (colon < 0) {
            throw IllegalStateException("missing number field")
        }
        var index = colon + 1
        while (index < text.length && text[index].isWhitespace()) {
            index += 1
        }
        val start = index
        while (index < text.length && text[index].isDigit()) {
            index += 1
        }
        return text.substring(start, index).toInt()
    }

    protected fun vectorCaseField(vectorName: String, caseName: String, fieldName: String): ByteArray {
        val vectorPath = Path.of("..", "..", "vectors", vectorName)
        val text = Files.readString(vectorPath)
        val caseIndex = text.indexOf("\"$caseName\"")
        if (caseIndex < 0) {
            throw IllegalStateException("missing vector case")
        }
        val match = Regex("\"$fieldName\"\\s*:\\s*\"([^\"]+)\"").find(text, caseIndex)
            ?: throw IllegalStateException("missing vector field")
        return base64UrlBytes(match.groupValues[1])
    }

    protected fun nativeEnvelope(status: ReallyMeNativeStatus, payload: ByteArray = ByteArray(0)): ByteArray =
        nativeEnvelope(status.code, payload)

    protected fun nativeEnvelope(statusCode: Int, payload: ByteArray): ByteArray =
        byteArrayOf(
            ((statusCode ushr 24) and 0xff).toByte(),
            ((statusCode ushr 16) and 0xff).toByte(),
            ((statusCode ushr 8) and 0xff).toByte(),
            (statusCode and 0xff).toByte(),
        ) + payload

    protected fun malformedDerEcdsaSignature(): ByteArray =
        DERSequence(
            arrayOf<ASN1Encodable>(
                DEROctetString(byteArrayOf(0x01)),
                DEROctetString(byteArrayOf(0x02)),
            ),
        ).encoded

    protected fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
