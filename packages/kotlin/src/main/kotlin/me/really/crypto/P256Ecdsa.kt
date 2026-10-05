// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import java.math.BigInteger
import java.security.MessageDigest
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.math.ec.FixedPointCombMultiplier

/**
 * Deterministic P-256 ECDSA over SHA-256 backed by BouncyCastle.
 *
 * JCA `Signature` providers generally choose fresh randomness for ECDSA. The
 * ReallyMe package contract needs deterministic DER signatures that reproduce
 * the Rust/Swift vectors byte-for-byte, so this wrapper uses RFC 6979 nonces
 * and emits DER-encoded `(r, s)`.
 */
public object ReallyMeP256Ecdsa {
    public const val SECRET_KEY_LENGTH: Int = 32
    public const val COMPRESSED_PUBLIC_KEY_LENGTH: Int = 33
    public const val UNCOMPRESSED_PUBLIC_KEY_LENGTH: Int = 65
    public const val DER_SIGNATURE_MAX_LENGTH: Int = 72
    public const val JOSE_SIGNATURE_LENGTH: Int = 64

    private val domain: ECDomainParameters =
        ECDomainParameters(SECNamedCurves.getByName("secp256r1"))

    public fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        return withRandomSecretCandidate(
            length = SECRET_KEY_LENGTH,
            isValid = { secretKey ->
                val scalar = BigInteger(1, secretKey)
                scalar.signum() > 0 && scalar < domain.n
            },
        ) { secretKey ->
            Pair(derivePublicKey(secretKey), secretKey.copyOf())
        }
    }

    public fun deriveKeyPair(secretKey: ByteArray): Pair<ByteArray, ByteArray> =
        Pair(derivePublicKey(secretKey), secretKey.copyOf())

    public fun derivePublicKey(secretKey: ByteArray): ByteArray {
        val scalar = validatedScalar(secretKey)
        return FixedPointCombMultiplier().multiply(domain.g, scalar).normalize().getEncoded(true)
    }

    public fun sign(message: ByteArray, secretKey: ByteArray): ByteArray {
        val scalar = validatedScalar(secretKey)
        val digest = MessageDigest.getInstance("SHA-256").digest(message)
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        signer.init(true, ECPrivateKeyParameters(scalar, domain))
        val components = signer.generateSignature(digest)
        return encodeDerSignature(components[0], components[1])
    }

    /**
     * Returns the canonical low-S form of a canonical DER signature.
     *
     * This is intended for signatures returned by HSMs and Android Keystore.
     * It validates the representation but does not verify authenticity against
     * a message or public key.
     */
    public fun normalizeDerSignatureLowS(signature: ByteArray): ByteArray {
        val (r, s) = decodeCanonicalDerSignature(signature)
        val normalizedS = normalizeS(s)
        return encodeDerSignature(r, normalizedS)
    }

    /**
     * Returns the canonical low-S form of an exact 64-byte JOSE `r || s`
     * signature without transcoding through DER.
     */
    public fun normalizeJoseSignatureLowS(signature: ByteArray): ByteArray {
        if (signature.size != JOSE_SIGNATURE_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val rBytes = signature.copyOfRange(0, SECRET_KEY_LENGTH)
        val sBytes = signature.copyOfRange(SECRET_KEY_LENGTH, signature.size)
        val r = BigInteger(1, rBytes)
        val s = BigInteger(1, sBytes)
        if (r.signum() <= 0 || r >= domain.n || s.signum() <= 0 || s >= domain.n) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val output = ByteArray(JOSE_SIGNATURE_LENGTH)
        scalarToFixedWidth(r).copyInto(output, destinationOffset = 0)
        scalarToFixedWidth(normalizeS(s)).copyInto(output, destinationOffset = SECRET_KEY_LENGTH)
        return output
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
        val digest = MessageDigest.getInstance("SHA-256").digest(message)
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

    private fun normalizeS(s: BigInteger): BigInteger =
        if (s > domain.n.shiftRight(1)) domain.n.subtract(s) else s

    private fun scalarToFixedWidth(scalar: BigInteger): ByteArray {
        val encoded = scalar.toByteArray()
        val withoutSignByte = if (encoded.size == SECRET_KEY_LENGTH + 1 && encoded[0] == 0.toByte()) {
            encoded.copyOfRange(1, encoded.size)
        } else {
            encoded
        }
        if (withoutSignByte.isEmpty() || withoutSignByte.size > SECRET_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val output = ByteArray(SECRET_KEY_LENGTH)
        withoutSignByte.copyInto(output, destinationOffset = SECRET_KEY_LENGTH - withoutSignByte.size)
        return output
    }

    private fun decodeDerSignature(signature: ByteArray): Pair<BigInteger, BigInteger> {
        val (r, s) = try {
            val sequence = ASN1Sequence.getInstance(signature)
            if (sequence.size() != 2) {
                throw ReallyMeCryptoException.InvalidInput()
            }
            Pair(
                ASN1Integer.getInstance(sequence.getObjectAt(0)).positiveValue,
                ASN1Integer.getInstance(sequence.getObjectAt(1)).positiveValue,
            )
        } catch (_: RuntimeException) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        if (r.signum() <= 0 || r >= domain.n || s.signum() <= 0 || s >= domain.n) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return Pair(r, s)
    }

    private fun decodeCanonicalDerSignature(signature: ByteArray): Pair<BigInteger, BigInteger> {
        if (signature.isEmpty() || signature.size > DER_SIGNATURE_MAX_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val components = decodeDerSignature(signature)
        // BouncyCastle accepts some BER and non-minimal INTEGER encodings. A
        // byte-for-byte DER round trip makes this public normalization boundary
        // strict and keeps it aligned with the Rust implementation.
        if (!encodeDerSignature(components.first, components.second).contentEquals(signature)) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return components
    }
}
