// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import java.math.BigInteger
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence

/** Admit only canonical DER and positive, in-range ECDSA scalars. */
internal fun decodeCanonicalEcdsaDer(
    signature: ByteArray,
    order: BigInteger,
    maximumLength: Int,
): Pair<BigInteger, BigInteger> {
    if (signature.isEmpty() || signature.size > maximumLength) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    val (r, s) = try {
        val sequence = ASN1Sequence.getInstance(signature)
        if (sequence.size() != 2) throw ReallyMeCryptoException.InvalidInput()
        Pair(
            ASN1Integer.getInstance(sequence.getObjectAt(0)).value,
            ASN1Integer.getInstance(sequence.getObjectAt(1)).value,
        )
    } catch (_: RuntimeException) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    if (r.signum() <= 0 || r >= order || s.signum() <= 0 || s >= order) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    // Parsing alone admits BER lengths and other alternate representations.
    // Re-encoding the scalar values rejects those aliases without imposing a
    // low-S policy on interoperable signature verification.
    val canonical = DERSequence(arrayOf(ASN1Integer(r), ASN1Integer(s))).encoded
    if (!canonical.contentEquals(signature)) throw ReallyMeCryptoException.InvalidInput()
    return Pair(r, s)
}
