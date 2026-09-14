// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto.conformance

import fr.acinq.secp256k1.Secp256k1
import java.math.BigInteger
import java.nio.file.Files
import java.security.GeneralSecurityException
import java.util.Arrays
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHAKEDigest
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.macs.KMAC
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.signers.MLDSASigner
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal fun readVector(name: String): String {
    val configured = System.getProperty("reallyme.crypto.vectors.dir")
    val vectorsDir = if (configured.isNullOrBlank()) {
        Path("../../../../vectors")
    } else {
        Path(configured)
    }
    return Files.readString(vectorsDir.resolve(name))
}

internal fun concat(vararg parts: ByteArray): ByteArray {
    val totalLength = parts.fold(0) { acc, part -> acc + part.size }
    val out = ByteArray(totalLength)
    var offset = 0
    for (part in parts) {
        part.copyInto(out, destinationOffset = offset)
        offset += part.size
    }
    return out
}

internal fun xofShake256(input: ByteArray, outputLength: Int): ByteArray {
    val digest = SHAKEDigest(256)
    digest.update(input, 0, input.size)
    val out = ByteArray(outputLength)
    digest.doOutput(out, 0, out.size)
    return out
}

internal fun sha3_256(input: ByteArray): ByteArray {
    val digest = SHA3Digest(256)
    digest.update(input, 0, input.size)
    val out = ByteArray(32)
    digest.doFinal(out, 0)
    return out
}

internal object Base64Url {
    fun decode(value: String): ByteArray {
        require(value.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        return java.util.Base64.getUrlDecoder().decode(value)
    }

    fun encode(value: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value)
}

internal data class KotlinJwkSpec(
    val alg: String,
    val crv: String,
    val kty: String,
    val keyUse: String,
    val publicKeyLength: Int,
)

internal data class ParsedKotlinJwk(val alg: String, val publicKey: ByteArray)

internal object KotlinJwk {
    fun toJcs(alg: String, publicKey: ByteArray): String {
        val spec = spec(alg)
        require(publicKey.size == spec.publicKeyLength)
        return if (spec.kty == "EC") {
            val uncompressed = BouncyCastleVectors.decompressEcPublicKey(curveName(alg), publicKey)
            val x = Base64Url.encode(uncompressed.copyOfRange(1, 33))
            val y = Base64Url.encode(uncompressed.copyOfRange(33, 65))
            """{"alg":${jsonString(spec.alg)},"crv":${jsonString(spec.crv)},"kty":"EC","use":"sig","x":${jsonString(x)},"y":${jsonString(y)}}"""
        } else {
            val encodedPublicKey = Base64Url.encode(publicKey)
            if (spec.kty == "AKP") {
                """{"alg":${jsonString(spec.alg)},"kty":"AKP","pub":${jsonString(encodedPublicKey)},"use":${jsonString(spec.keyUse)}}"""
            } else {
                """{"alg":${jsonString(spec.alg)},"crv":${jsonString(spec.crv)},"kty":"OKP","use":${jsonString(spec.keyUse)},"x":${jsonString(encodedPublicKey)}}"""
            }
        }
    }

    fun fromJcs(value: String): ParsedKotlinJwk {
        val jwk = JsonObject.parse(value)
        val kty = jwk.requiredString("kty")
        val keyIdentifier = if (kty == "AKP") jwk.requiredString("alg") else jwk.requiredString("crv")
        val spec = spec(keyIdentifier)
        require(jwk.requiredString("kty") == spec.kty)
        require(jwk.requiredString("alg") == spec.alg)
        require(jwk.requiredString("use") == spec.keyUse)

        val publicKey = if (spec.kty == "EC") {
            BouncyCastleVectors.compressEcPublicKey(
                curveName(keyIdentifier),
                Base64Url.decode(jwk.requiredString("x")),
                Base64Url.decode(jwk.requiredString("y")),
            )
        } else if (spec.kty == "AKP") {
            Base64Url.decode(jwk.requiredString("pub"))
        } else {
            Base64Url.decode(jwk.requiredString("x"))
        }
        require(publicKey.size == spec.publicKeyLength)
        return ParsedKotlinJwk(keyIdentifier, publicKey)
    }

    private fun spec(alg: String): KotlinJwkSpec = when (alg) {
        "Ed25519" -> KotlinJwkSpec("EdDSA", "Ed25519", "OKP", "sig", 32)
        "X25519" -> KotlinJwkSpec("ECDH-ES", "X25519", "OKP", "enc", 32)
        "P-256" -> KotlinJwkSpec("ES256", "P-256", "EC", "sig", 33)
        "secp256k1" -> KotlinJwkSpec("ES256K", "secp256k1", "EC", "sig", 33)
        "ML-DSA-44" -> KotlinJwkSpec(alg, alg, "AKP", "sig", 1_312)
        "ML-DSA-65" -> KotlinJwkSpec(alg, alg, "AKP", "sig", 1_952)
        "ML-DSA-87" -> KotlinJwkSpec(alg, alg, "AKP", "sig", 2_592)
        "ML-KEM-512" -> KotlinJwkSpec(alg, alg, "AKP", "enc", 800)
        "ML-KEM-768" -> KotlinJwkSpec(alg, alg, "AKP", "enc", 1_184)
        "ML-KEM-1024" -> KotlinJwkSpec(alg, alg, "AKP", "enc", 1_568)
        "SLH-DSA-SHA2-128s" -> KotlinJwkSpec(alg, alg, "AKP", "sig", 32)
        "X-Wing-768" -> KotlinJwkSpec(alg, alg, "AKP", "enc", 1_216)
        else -> error("unsupported JWK algorithm")
    }

    private fun curveName(alg: String): String = when (alg) {
        "P-256" -> "secp256r1"
        "secp256k1" -> "secp256k1"
        else -> error("unsupported EC JWK algorithm")
    }

    private fun jsonString(value: String): String =
        buildString {
            append('"')
            for (char in value) {
                when (char) {
                    '"' -> append("\\\"")
                    '\\' -> append("\\\\")
                    '\b' -> append("\\b")
                    '\u000C' -> append("\\f")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(char)
                }
            }
            append('"')
        }
}

internal class JsonObject private constructor(private val fields: Map<String, Any?>) {
    fun requiredString(name: String): String =
        fields[name] as? String ?: error("missing string field $name")

    fun optionalString(name: String): String? =
        fields[name] as? String

    fun requiredLong(name: String): Long =
        fields[name] as? Long ?: error("missing number field $name")

    fun requiredStringArray(name: String): List<String> =
        (fields[name] as? List<*>)?.map { it as? String ?: error("invalid string array $name") }
            ?: error("missing string array $name")

    fun requiredObject(name: String): JsonObject {
        return JsonObject(requireStringKeyedMap(fields[name], "missing object field $name"))
    }

    fun requiredObjectArray(name: String): List<JsonObject> =
        (fields[name] as? List<*>)?.map {
            JsonObject(requireStringKeyedMap(it, "invalid object array $name"))
        } ?: error("missing object array $name")

    companion object {
        fun parse(input: String): JsonObject {
            val parser = JsonParser(input)
            val value = parser.parseValue()
            parser.requireEnd()

            return JsonObject(requireStringKeyedMap(value, "expected object"))
        }
    }
}

private fun requireStringKeyedMap(value: Any?, failureMessage: String): Map<String, Any?> {
    val untyped = value as? Map<*, *> ?: error(failureMessage)
    val typed = LinkedHashMap<String, Any?>(untyped.size)
    for ((key, entryValue) in untyped) {
        val stringKey = key as? String ?: error(failureMessage)
        typed[stringKey] = entryValue
    }
    return typed
}

internal class JsonParser(private val input: String) {
    private var offset: Int = 0

    fun parseValue(): Any? {
        skipWhitespace()
        return when (peek()) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> parseString()
            't' -> parseLiteral("true", true)
            'f' -> parseLiteral("false", false)
            'n' -> parseLiteral("null", null)
            else -> parseNumber()
        }
    }

    fun requireEnd() {
        skipWhitespace()
        require(offset == input.length)
    }

    private fun parseObject(): Map<String, Any?> {
        consume('{')
        val result = linkedMapOf<String, Any?>()
        skipWhitespace()
        if (tryConsume('}')) {
            return result
        }

        while (true) {
            val key = parseString()
            consume(':')
            result[key] = parseValue()
            if (tryConsume('}')) {
                return result
            }
            consume(',')
        }
    }

    private fun parseArray(): List<Any?> {
        consume('[')
        val result = mutableListOf<Any?>()
        skipWhitespace()
        if (tryConsume(']')) {
            return result
        }

        while (true) {
            result.add(parseValue())
            if (tryConsume(']')) {
                return result
            }
            consume(',')
        }
    }

    private fun parseString(): String {
        consume('"')
        val builder = StringBuilder()
        while (offset < input.length) {
            val char = input[offset++]
            when (char) {
                '"' -> return builder.toString()
                '\\' -> builder.append(parseEscape())
                else -> builder.append(char)
            }
        }
        error("unterminated string")
    }

    private fun parseEscape(): Char {
        require(offset < input.length)
        return when (val escaped = input[offset++]) {
            '"', '\\', '/' -> escaped
            'b' -> '\b'
            'f' -> '\u000C'
            'n' -> '\n'
            'r' -> '\r'
            't' -> '\t'
            'u' -> parseUnicodeEscape()
            else -> error("invalid escape")
        }
    }

    private fun parseUnicodeEscape(): Char {
        require(offset + 4 <= input.length)
        val value = input.substring(offset, offset + 4).toInt(16)
        offset += 4
        return value.toChar()
    }

    private fun parseLiteral(token: String, value: Any?): Any? {
        require(input.startsWith(token, offset))
        offset += token.length
        return value
    }

    private fun parseNumber(): Number {
        val start = offset
        if (peek() == '-') {
            offset += 1
        }
        while (offset < input.length && input[offset].isDigit()) {
            offset += 1
        }
        return input.substring(start, offset).toLong()
    }

    private fun consume(expected: Char) {
        skipWhitespace()
        require(offset < input.length && input[offset] == expected)
        offset += 1
    }

    private fun tryConsume(expected: Char): Boolean {
        skipWhitespace()
        if (offset < input.length && input[offset] == expected) {
            offset += 1
            return true
        }
        return false
    }

    private fun peek(): Char {
        require(offset < input.length)
        return input[offset]
    }

    private fun skipWhitespace() {
        while (offset < input.length && input[offset].isWhitespace()) {
            offset += 1
        }
    }
}
