// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import org.bouncycastle.asn1.pkcs.RSAPublicKey

public enum class ReallyMeRsaPublicKeyDerEncoding {
    PKCS1,
    SPKI,
}

private data class RsaPkcs1v15Suite(val signatureAlgorithm: String)

private data class RsaPssSuite(
    val digestAlgorithm: String,
    val mgf1DigestAlgorithm: String,
    val saltLength: Int,
)

/**
 * RSA signature verification through JCA/JCE with BouncyCastle fallback.
 *
 * RSA is verification-only in this SDK. The route exists for X.509, eMRTD
 * passive authentication, and legacy interop; adding RSA signing would require
 * a separate key-residency and padding-policy review.
 */
public object ReallyMeRsa {
    public fun verify(
        algorithm: ReallyMeSignatureAlgorithm,
        signature: ByteArray,
        message: ByteArray,
        publicKeyDer: ByteArray,
        publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding,
    ) {
        val publicKey = parsePublicKey(publicKeyDer, publicKeyEncoding)
        val pkcs1v15 = pkcs1v15Suite(algorithm)
        if (pkcs1v15 != null) {
            verifyPkcs1v15(pkcs1v15, signature, message, publicKey)
            return
        }
        val pss = pssSuite(algorithm)
        if (pss != null) {
            verifyPss(pss, signature, message, publicKey)
            return
        }
        throw ReallyMeCryptoException.UnsupportedAlgorithm()
    }

    private fun verifyPkcs1v15(
        suite: RsaPkcs1v15Suite,
        signature: ByteArray,
        message: ByteArray,
        publicKey: PublicKey,
    ) {
        try {
            val verifier = ReallyMeJceProviders.signature(suite.signatureAlgorithm)
            verifier.initVerify(publicKey)
            verifier.update(message)
            if (!verifier.verify(signature)) {
                throw ReallyMeCryptoException.InvalidSignature()
            }
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun verifyPss(
        suite: RsaPssSuite,
        signature: ByteArray,
        message: ByteArray,
        publicKey: PublicKey,
    ) {
        try {
            val verifier = ReallyMeJceProviders.signature("RSASSA-PSS")
            verifier.setParameter(
                PSSParameterSpec(
                    suite.digestAlgorithm,
                    "MGF1",
                    MGF1ParameterSpec(suite.mgf1DigestAlgorithm),
                    suite.saltLength,
                    1,
                ),
            )
            verifier.initVerify(publicKey)
            verifier.update(message)
            if (!verifier.verify(signature)) {
                throw ReallyMeCryptoException.InvalidSignature()
            }
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    private fun parsePublicKey(
        publicKeyDer: ByteArray,
        encoding: ReallyMeRsaPublicKeyDerEncoding,
    ): PublicKey {
        if (publicKeyDer.isEmpty()) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val keyFactory = try {
            KeyFactory.getInstance("RSA")
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }

        return try {
            when (encoding) {
                ReallyMeRsaPublicKeyDerEncoding.PKCS1 -> {
                    val parsed = RSAPublicKey.getInstance(publicKeyDer)
                    keyFactory.generatePublic(RSAPublicKeySpec(parsed.modulus, parsed.publicExponent))
                }
                ReallyMeRsaPublicKeyDerEncoding.SPKI ->
                    keyFactory.generatePublic(X509EncodedKeySpec(publicKeyDer))
            }
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        } catch (_: GeneralSecurityException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun pkcs1v15Suite(algorithm: ReallyMeSignatureAlgorithm): RsaPkcs1v15Suite? =
        when (algorithm) {
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA1 -> RsaPkcs1v15Suite("SHA1withRSA")
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA256 -> RsaPkcs1v15Suite("SHA256withRSA")
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA384 -> RsaPkcs1v15Suite("SHA384withRSA")
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA512 -> RsaPkcs1v15Suite("SHA512withRSA")
            else -> null
        }

    private fun pssSuite(algorithm: ReallyMeSignatureAlgorithm): RsaPssSuite? =
        when (algorithm) {
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA1_MGF1_SHA1 ->
                RsaPssSuite("SHA-1", "SHA-1", 20)
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA256_MGF1_SHA256 ->
                RsaPssSuite("SHA-256", "SHA-256", 32)
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA384_MGF1_SHA384 ->
                RsaPssSuite("SHA-384", "SHA-384", 48)
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA512_MGF1_SHA512 ->
                RsaPssSuite("SHA-512", "SHA-512", 64)
            else -> null
        }
}
