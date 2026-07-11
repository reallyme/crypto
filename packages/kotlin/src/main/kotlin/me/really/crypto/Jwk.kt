// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.util.Base64
import org.bouncycastle.asn1.sec.SECNamedCurves

public enum class ReallyMeJwkAlgorithm(public val algorithmName: String) {
    ED25519("Ed25519"),
    X25519("X25519"),
    P256("P-256"),
    SECP256K1("secp256k1"),
    ML_DSA_44("ML-DSA-44"),
    ML_DSA_65("ML-DSA-65"),
    ML_DSA_87("ML-DSA-87"),
    ML_KEM_512("ML-KEM-512"),
    ML_KEM_768("ML-KEM-768"),
    ML_KEM_1024("ML-KEM-1024"),
    SLH_DSA_SHA2_128S("SLH-DSA-SHA2-128s"),
    X_WING_768("X-Wing-768"),
    X_WING_1024("X-Wing-1024"),
}

public data class ReallyMeJwkDocument(
    public val algorithm: ReallyMeJwkAlgorithm,
    public val kty: String,
    public val alg: String,
    public val keyUse: String,
    public val crv: String?,
    public val x: String?,
    public val y: String?,
    public val publicKey: String?,
)

public class ReallyMeJwkKey(
    public val algorithm: ReallyMeJwkAlgorithm,
    public val publicKey: ByteArray,
    public val jwk: ReallyMeJwkDocument,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeJwkKey &&
            algorithm == other.algorithm &&
            publicKey.contentEquals(other.publicKey) &&
            jwk == other.jwk

    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + jwk.hashCode()
        return result
    }
}

public data class ReallyMeJwks(
    public val keys: List<ReallyMeJwkDocument>,
)

private data class ReallyMeJwkSpec(
    val alg: String,
    val crv: String?,
    val kty: String,
    val keyUse: String,
    val publicKeyLength: Int,
)

/**
 * Native JWK conversion for Kotlin/JVM and Android package consumers.
 *
 * The facade keeps JWK as JSON and base64url work in the host language instead
 * of routing envelope serialization through the Rust C ABI.
 */
public object ReallyMeJwk {
    public fun toJwk(
        algorithm: ReallyMeJwkAlgorithm,
        publicKey: ByteArray,
    ): ReallyMeJwkDocument {
        val spec = spec(algorithm.algorithmName)
        if (publicKey.size != spec.publicKeyLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        if (spec.kty == "EC") {
            val uncompressed = decompressEcPublicKey(algorithm, publicKey)
            return ReallyMeJwkDocument(
                algorithm = algorithm,
                kty = spec.kty,
                alg = spec.alg,
                keyUse = spec.keyUse,
                crv = spec.crv,
                x = Base64Url.encode(uncompressed.copyOfRange(1, 33)),
                y = Base64Url.encode(uncompressed.copyOfRange(33, 65)),
                publicKey = null,
            )
        }

        val encodedPublicKey = Base64Url.encode(publicKey)
        return ReallyMeJwkDocument(
            algorithm = algorithm,
            kty = spec.kty,
            alg = spec.alg,
            keyUse = spec.keyUse,
            crv = spec.crv,
            x = if (spec.kty == "OKP") encodedPublicKey else null,
            y = null,
            publicKey = if (spec.kty == "AKP") encodedPublicKey else null,
        )
    }

    public fun toJcs(jwk: ReallyMeJwkDocument): String = when (jwk.kty) {
        "EC" -> {
            val crv = jwk.crv ?: throw ReallyMeCryptoException.InvalidInput()
            val x = jwk.x ?: throw ReallyMeCryptoException.InvalidInput()
            val y = jwk.y ?: throw ReallyMeCryptoException.InvalidInput()
            """{"alg":${jsonString(jwk.alg)},"crv":${jsonString(crv)},"kty":"EC","use":${jsonString(jwk.keyUse)},"x":${jsonString(x)},"y":${jsonString(y)}}"""
        }
        "OKP" -> {
            val crv = jwk.crv ?: throw ReallyMeCryptoException.InvalidInput()
            val x = jwk.x ?: throw ReallyMeCryptoException.InvalidInput()
            """{"alg":${jsonString(jwk.alg)},"crv":${jsonString(crv)},"kty":"OKP","use":${jsonString(jwk.keyUse)},"x":${jsonString(x)}}"""
        }
        "AKP" -> {
            val publicKey = jwk.publicKey ?: throw ReallyMeCryptoException.InvalidInput()
            """{"alg":${jsonString(jwk.alg)},"kty":"AKP","pub":${jsonString(publicKey)},"use":${jsonString(jwk.keyUse)}}"""
        }
        else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
    }

    public fun fromJwkJson(json: String): ReallyMeJwkKey {
        val objectMap = parseFlatStringObject(json)
        val kty = objectMap["kty"] ?: throw ReallyMeCryptoException.InvalidInput()
        val algorithmName = if (kty == "AKP") {
            objectMap["alg"] ?: throw ReallyMeCryptoException.InvalidInput()
        } else {
            objectMap["crv"] ?: throw ReallyMeCryptoException.InvalidInput()
        }
        val spec = spec(algorithmName)
        val algorithm = algorithm(algorithmName)
        if (
            kty != spec.kty ||
            objectMap["alg"] != spec.alg ||
            objectMap["use"] != spec.keyUse
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        val publicKey = when (spec.kty) {
            "EC" -> compressEcPublicKey(
                algorithm,
                Base64Url.decode(objectMap["x"] ?: throw ReallyMeCryptoException.InvalidInput()),
                Base64Url.decode(objectMap["y"] ?: throw ReallyMeCryptoException.InvalidInput()),
            )
            "AKP" -> Base64Url.decode(objectMap["pub"] ?: throw ReallyMeCryptoException.InvalidInput())
            "OKP" -> Base64Url.decode(objectMap["x"] ?: throw ReallyMeCryptoException.InvalidInput())
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

        if (publicKey.size != spec.publicKeyLength) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val jwk = toJwk(algorithm, publicKey)
        return ReallyMeJwkKey(algorithm, publicKey, jwk)
    }

    public fun toJwks(keys: List<ReallyMeJwkDocument>): ReallyMeJwks =
        ReallyMeJwks(keys.toList())

    public fun fromJwksJson(json: String): List<ReallyMeJwkKey> =
        FlatJwksJsonParser(json).parse().map { fromJwkJson(it) }

    public fun publicKeyBytes(jwk: ReallyMeJwkDocument): ByteArray =
        fromJwkJson(toJcs(jwk)).publicKey

    private fun spec(algorithmName: String): ReallyMeJwkSpec = when (algorithmName) {
        "Ed25519" -> ReallyMeJwkSpec("EdDSA", "Ed25519", "OKP", "sig", 32)
        "X25519" -> ReallyMeJwkSpec("ECDH-ES", "X25519", "OKP", "enc", 32)
        "P-256" -> ReallyMeJwkSpec("ES256", "P-256", "EC", "sig", 33)
        "secp256k1" -> ReallyMeJwkSpec("ES256K", "secp256k1", "EC", "sig", 33)
        "ML-DSA-44" -> ReallyMeJwkSpec(algorithmName, null, "AKP", "sig", 1_312)
        "ML-DSA-65" -> ReallyMeJwkSpec(algorithmName, null, "AKP", "sig", 1_952)
        "ML-DSA-87" -> ReallyMeJwkSpec(algorithmName, null, "AKP", "sig", 2_592)
        "ML-KEM-512" -> ReallyMeJwkSpec(algorithmName, null, "AKP", "enc", 800)
        "ML-KEM-768" -> ReallyMeJwkSpec(algorithmName, null, "AKP", "enc", 1_184)
        "ML-KEM-1024" -> ReallyMeJwkSpec(algorithmName, null, "AKP", "enc", 1_568)
        "SLH-DSA-SHA2-128s" -> ReallyMeJwkSpec(algorithmName, null, "AKP", "sig", 32)
        "X-Wing-768" -> ReallyMeJwkSpec(algorithmName, null, "AKP", "enc", 1_216)
        "X-Wing-1024" -> ReallyMeJwkSpec(algorithmName, null, "AKP", "enc", 1_600)
        else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
    }

    private fun algorithm(algorithmName: String): ReallyMeJwkAlgorithm =
        ReallyMeJwkAlgorithm.entries.firstOrNull { it.algorithmName == algorithmName }
            ?: throw ReallyMeCryptoException.UnsupportedAlgorithm()

    private fun decompressEcPublicKey(
        algorithm: ReallyMeJwkAlgorithm,
        publicKey: ByteArray,
    ): ByteArray {
        if (publicKey.size != 33) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val domainName = when (algorithm) {
            ReallyMeJwkAlgorithm.P256 -> "secp256r1"
            ReallyMeJwkAlgorithm.SECP256K1 -> "secp256k1"
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }
        val domain = SECNamedCurves.getByName(domainName)
        return try {
            domain.curve.decodePoint(publicKey).normalize().getEncoded(false)
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun compressEcPublicKey(
        algorithm: ReallyMeJwkAlgorithm,
        x: ByteArray,
        y: ByteArray,
    ): ByteArray {
        if (x.size != 32 || y.size != 32) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val compressed = ByteArray(33)
        compressed[0] = if ((y.last().toInt() and 1) == 0) 0x02 else 0x03
        x.copyInto(compressed, destinationOffset = 1)
        decompressEcPublicKey(algorithm, compressed)
        return compressed
    }

    private fun jsonString(value: String): String {
        val out = StringBuilder()
        out.append('"')
        for (char in value) {
            when (char) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                else -> {
                    if (char.code < 0x20) {
                        throw ReallyMeCryptoException.InvalidInput()
                    }
                    out.append(char)
                }
            }
        }
        out.append('"')
        return out.toString()
    }

    private fun parseFlatStringObject(json: String): Map<String, String> {
        val parser = FlatJwkJsonParser(json)
        return parser.parse()
    }
}

private class FlatJwksJsonParser(private val json: String) {
    private var index: Int = 0

    fun parse(): List<String> {
        skipWhitespace()
        consume('{')
        skipWhitespace()
        if (parseString() != "keys") {
            throw ReallyMeCryptoException.InvalidInput()
        }
        skipWhitespace()
        consume(':')
        skipWhitespace()
        consume('[')
        skipWhitespace()
        val keys = mutableListOf<String>()
        if (peek() == ']') {
            consume(']')
            finish()
            return keys
        }
        while (true) {
            keys += parseObjectJson()
            skipWhitespace()
            when (peek()) {
                ',' -> {
                    consume(',')
                    skipWhitespace()
                }
                ']' -> {
                    consume(']')
                    finish()
                    return keys
                }
                else -> throw ReallyMeCryptoException.InvalidInput()
            }
        }
    }

    private fun finish() {
        skipWhitespace()
        consume('}')
        skipWhitespace()
        if (index != json.length) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun parseObjectJson(): String {
        val start = index
        consume('{')
        var inString = false
        var escaped = false
        var depth = 1
        while (index < json.length) {
            val char = json[index]
            index += 1
            if (inString) {
                if (escaped) {
                    escaped = false
                } else if (char == '\\') {
                    escaped = true
                } else if (char == '"') {
                    inString = false
                }
            } else {
                when (char) {
                    '"' -> inString = true
                    '{' -> depth += 1
                    '}' -> {
                        depth -= 1
                        if (depth == 0) {
                            return json.substring(start, index)
                        }
                    }
                }
            }
        }
        throw ReallyMeCryptoException.InvalidInput()
    }

    private fun parseString(): String {
        consume('"')
        val start = index
        while (index < json.length && json[index] != '"') {
            if (json[index] == '\\' || json[index].code < 0x20) {
                throw ReallyMeCryptoException.InvalidInput()
            }
            index += 1
        }
        val value = json.substring(start, index)
        consume('"')
        return value
    }

    private fun skipWhitespace() {
        while (index < json.length && json[index].isWhitespace()) {
            index += 1
        }
    }

    private fun consume(expected: Char) {
        if (peek() != expected) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        index += 1
    }

    private fun peek(): Char {
        if (index >= json.length) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return json[index]
    }
}

private object Base64Url {
    fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun decode(encoded: String): ByteArray = try {
        if (encoded.length % 4 == 1) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        Base64.getUrlDecoder().decode(encoded)
    } catch (_: IllegalArgumentException) {
        throw ReallyMeCryptoException.InvalidInput()
    }
}

private class FlatJwkJsonParser(private val json: String) {
    private var index: Int = 0

    fun parse(): Map<String, String> {
        val fields = mutableMapOf<String, String>()
        skipWhitespace()
        consume('{')
        skipWhitespace()
        if (peek() == '}') {
            consume('}')
            return fields
        }
        while (true) {
            val key = parseString()
            skipWhitespace()
            consume(':')
            skipWhitespace()
            val value = parseString()
            if (fields.put(key, value) != null) {
                throw ReallyMeCryptoException.InvalidInput()
            }
            skipWhitespace()
            when (peek()) {
                ',' -> {
                    consume(',')
                    skipWhitespace()
                }
                '}' -> {
                    consume('}')
                    skipWhitespace()
                    if (index != json.length) {
                        throw ReallyMeCryptoException.InvalidInput()
                    }
                    return fields
                }
                else -> throw ReallyMeCryptoException.InvalidInput()
            }
        }
    }

    private fun parseString(): String {
        consume('"')
        val out = StringBuilder()
        while (index < json.length) {
            val char = json[index]
            index += 1
            when (char) {
                '"' -> return out.toString()
                '\\' -> out.append(parseEscape())
                else -> {
                    if (char.code < 0x20) {
                        throw ReallyMeCryptoException.InvalidInput()
                    }
                    out.append(char)
                }
            }
        }
        throw ReallyMeCryptoException.InvalidInput()
    }

    private fun parseEscape(): Char {
        if (index >= json.length) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val escaped = json[index]
        index += 1
        return when (escaped) {
            '"', '\\', '/' -> escaped
            'b' -> '\b'
            'f' -> '\u000C'
            'n' -> '\n'
            'r' -> '\r'
            't' -> '\t'
            else -> throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun skipWhitespace() {
        while (index < json.length && json[index].isWhitespace()) {
            index += 1
        }
    }

    private fun consume(expected: Char) {
        if (peek() != expected) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        index += 1
    }

    private fun peek(): Char {
        if (index >= json.length) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return json[index]
    }
}
