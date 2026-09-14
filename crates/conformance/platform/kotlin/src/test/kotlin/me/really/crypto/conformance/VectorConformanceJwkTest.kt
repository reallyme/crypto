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

internal class VectorConformanceJwkTest : VectorConformanceTestSupport() {
    @Test
    fun nativeJwkVectorsMatchRustContract() {
        val vectorFile = JsonObject.parse(readVector("jwk.json"))
        val vectors = vectorFile.requiredObjectArray("vectors")
        val expectedAlgorithms = setOf(
            "Ed25519",
            "X25519",
            "P-256",
            "secp256k1",
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024",
            "SLH-DSA-SHA2-128s",
            "X-Wing-768",
        )
        assertEquals(expectedAlgorithms, vectors.map { it.requiredString("alg") }.toSet())
        assertEquals(expectedAlgorithms.size, vectors.size)
        for (vector in vectors) {
            val alg = vector.requiredString("alg")
            val publicKey = Base64Url.decode(vector.requiredString("public_key"))
            assertEquals(vector.requiredLong("public_key_length").toInt(), publicKey.size)
            assertEquals(vector.requiredString("jwk_jcs"), KotlinJwk.toJcs(alg, publicKey))
            val parsed = KotlinJwk.fromJcs(vector.requiredString("jwk_jcs"))
            assertEquals(alg, parsed.alg)
            assertTrue(parsed.publicKey.contentEquals(publicKey))

            when (vector.requiredString("multikey_status")) {
                "supported" -> assertTrue(vector.optionalString("multikey")?.startsWith("z") == true)
                "multicodec-missing" -> assertEquals(null, vector.optionalString("multikey"))
                else -> error("invalid JWK multikey status")
            }
            publicKey.fill(0)
            parsed.publicKey.fill(0)
        }
    }


}
