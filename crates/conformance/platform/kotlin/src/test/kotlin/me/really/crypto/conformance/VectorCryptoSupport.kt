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

internal object LibSecp256k1Vectors {
    private val provider: Secp256k1 by lazy {
        Secp256k1.get()
    }

    fun deriveSecp256k1PublicKey(secretKey: ByteArray): ByteArray {
        require(secretKey.size == 32)
        return provider.pubKeyCompress(provider.pubkeyCreate(secretKey))
    }
}

internal object BouncyCastleVectors {
    private val p256Domain: ECDomainParameters by lazy {
        ECDomainParameters(SECNamedCurves.getByName("secp256r1"))
    }

    private fun domain(curveName: String): ECDomainParameters =
        ECDomainParameters(SECNamedCurves.getByName(curveName))

    /// Returns the P-256 public key derived from `secretKey`, SEC1-encoded
    /// (`compressed = true` -> 33 bytes, else 65 bytes uncompressed).
    fun deriveP256PublicKey(secretKey: ByteArray, compressed: Boolean): ByteArray {
        require(secretKey.size == 32)
        val scalar = p256Domain.validatePrivateScalar(BigInteger(1, secretKey))
        return p256Domain.g.multiply(scalar).normalize().getEncoded(compressed)
    }

    fun deriveP256SharedSecret(secretKey: ByteArray, publicKey: ByteArray): ByteArray {
        require(secretKey.size == 32)
        val scalar = p256Domain.validatePrivateScalar(BigInteger(1, secretKey))
        val point = p256Domain.curve.decodePoint(publicKey).multiply(scalar).normalize()
        return point.affineXCoord.encoded
    }

    fun deriveSec1PublicKey(curveName: String, secretKey: ByteArray, compressed: Boolean): ByteArray {
        val curveDomain = domain(curveName)
        val scalar = curveDomain.validatePrivateScalar(BigInteger(1, secretKey))
        return curveDomain.g.multiply(scalar).normalize().getEncoded(compressed)
    }

    fun decompressEcPublicKey(curveName: String, publicKey: ByteArray): ByteArray {
        val curveDomain = domain(curveName)
        return curveDomain.curve.decodePoint(publicKey).normalize().getEncoded(false)
    }

    fun compressEcPublicKey(curveName: String, x: ByteArray, y: ByteArray): ByteArray {
        require(x.size == 32)
        require(y.size == 32)
        return decompressEcPublicKey(curveName, concat(byteArrayOf(0x04), x, y))
            .let { uncompressed ->
                val curveDomain = domain(curveName)
                curveDomain.curve.decodePoint(uncompressed).normalize().getEncoded(true)
            }
    }

    fun verifySec1Ecdsa(
        curveName: String,
        publicKeySec1: ByteArray,
        message: ByteArray,
        signatureDer: ByteArray,
    ): Boolean {
        val curveDomain = domain(curveName)
        val publicPoint = curveDomain.curve.decodePoint(publicKeySec1)
        val publicKey = ECPublicKeyParameters(publicPoint, curveDomain)
        val digest = when (curveName) {
            "secp384r1" -> {
                val out = ByteArray(48)
                val digest = SHA384Digest()
                digest.update(message, 0, message.size)
                digest.doFinal(out, 0)
                out
            }
            "secp521r1" -> {
                val out = ByteArray(64)
                val digest = SHA512Digest()
                digest.update(message, 0, message.size)
                digest.doFinal(out, 0)
                out
            }
            else -> return false
        }
        val sequence = try {
            ASN1Sequence.getInstance(signatureDer)
        } catch (_: RuntimeException) {
            return false
        }
        if (sequence.size() != 2) {
            return false
        }
        val r = try {
            ASN1Integer.getInstance(sequence.getObjectAt(0)).positiveValue
        } catch (_: RuntimeException) {
            return false
        }
        val s = try {
            ASN1Integer.getInstance(sequence.getObjectAt(1)).positiveValue
        } catch (_: RuntimeException) {
            return false
        }
        val verifier = ECDSASigner()
        verifier.init(false, publicKey)
        return verifier.verifySignature(digest, r, s)
    }

    fun deriveEd25519PublicKey(secretKey: ByteArray): ByteArray =
        Ed25519PrivateKeyParameters(secretKey, 0).generatePublicKey().encoded

    /// RFC 8032 Ed25519 is deterministic, so this reproduces the committed
    /// signature exactly.
    fun signEd25519(secretKey: ByteArray, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(secretKey, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }

    fun deriveX25519PublicKey(secretKey: ByteArray): ByteArray =
        X25519PrivateKeyParameters(secretKey, 0).generatePublicKey().encoded

    fun x25519SharedSecret(secretKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(secretKey, 0))
        val out = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(peerPublicKey, 0), out, 0)
        return out
    }
}
