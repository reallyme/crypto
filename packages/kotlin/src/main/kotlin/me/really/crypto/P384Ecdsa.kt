// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator

/**
 * Deterministic P-384 ECDSA over SHA-384 backed by BouncyCastle.
 *
 * The package contract needs reproducible DER signatures that match the Rust
 * vectors byte-for-byte, so this wrapper uses RFC 6979 nonces rather than JCA
 * provider randomness.
 */
public object ReallyMeP384Ecdsa {
    public const val SECRET_KEY_LENGTH: Int = 48
    public const val COMPRESSED_PUBLIC_KEY_LENGTH: Int = 49
    public const val UNCOMPRESSED_PUBLIC_KEY_LENGTH: Int = 97

    private val domain: ECDomainParameters =
        ECDomainParameters(SECNamedCurves.getByName("secp384r1"))

    public fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val random = SecureRandom()
        val secretKey = ByteArray(SECRET_KEY_LENGTH)
        repeat(1024) {
            random.nextBytes(secretKey)
            val scalar = BigInteger(1, secretKey)
            if (scalar.signum() > 0 && scalar < domain.n) {
                return Pair(derivePublicKey(secretKey), secretKey.copyOf())
            }
        }
        throw ReallyMeCryptoException.ProviderFailure()
    }

    public fun deriveKeyPair(secretKey: ByteArray): Pair<ByteArray, ByteArray> =
        Pair(derivePublicKey(secretKey), secretKey.copyOf())

    public fun derivePublicKey(secretKey: ByteArray): ByteArray {
        val scalar = validatedScalar(secretKey)
        return domain.g.multiply(scalar).normalize().getEncoded(true)
    }

    public fun sign(message: ByteArray, secretKey: ByteArray): ByteArray {
        val scalar = validatedScalar(secretKey)
        val digest = MessageDigest.getInstance("SHA-384").digest(message)
        val signer = ECDSASigner(HMacDSAKCalculator(SHA384Digest()))
        signer.init(true, ECPrivateKeyParameters(scalar, domain))
        val components = signer.generateSignature(digest)
        return encodeDerSignature(components[0], components[1])
    }

    public fun verify(signature: ByteArray, message: ByteArray, publicKey: ByteArray) {
        if (publicKey.size != COMPRESSED_PUBLIC_KEY_LENGTH &&
            publicKey.size != UNCOMPRESSED_PUBLIC_KEY_LENGTH
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        val point = try {
            domain.curve.decodePoint(publicKey)
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val (r, s) = decodeDerSignature(signature)
        val digest = MessageDigest.getInstance("SHA-384").digest(message)
        val verifier = ECDSASigner()
        verifier.init(false, ECPublicKeyParameters(point, domain))
        if (!verifier.verifySignature(digest, r, s)) {
            throw ReallyMeCryptoException.InvalidSignature()
        }
    }

    private fun validatedScalar(secretKey: ByteArray): BigInteger {
        if (secretKey.size != SECRET_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val scalar = BigInteger(1, secretKey)
        if (scalar.signum() <= 0 || scalar >= domain.n) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return scalar
    }

    private fun encodeDerSignature(r: BigInteger, s: BigInteger): ByteArray =
        DERSequence(arrayOf(ASN1Integer(r), ASN1Integer(s))).encoded

    private fun decodeDerSignature(signature: ByteArray): Pair<BigInteger, BigInteger> {
        val sequence = try {
            ASN1Sequence.getInstance(signature)
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        if (sequence.size() != 2) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val r = ASN1Integer.getInstance(sequence.getObjectAt(0)).positiveValue
        val s = ASN1Integer.getInstance(sequence.getObjectAt(1)).positiveValue
        if (r.signum() <= 0 || r >= domain.n || s.signum() <= 0 || s >= domain.n) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return Pair(r, s)
    }
}
