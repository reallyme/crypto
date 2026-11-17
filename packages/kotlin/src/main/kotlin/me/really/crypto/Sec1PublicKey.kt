// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

private const val SEC1_COMPRESSED_EVEN_PREFIX: Byte = 0x02
private const val SEC1_COMPRESSED_ODD_PREFIX: Byte = 0x03
private const val SEC1_UNCOMPRESSED_PREFIX: Byte = 0x04

internal fun requireCompressedSec1PublicKey(publicKey: ByteArray, compressedLength: Int) {
    val prefix = publicKey.firstOrNull()
    if (publicKey.size != compressedLength ||
        (prefix != SEC1_COMPRESSED_EVEN_PREFIX && prefix != SEC1_COMPRESSED_ODD_PREFIX)
    ) {
        throw ReallyMeCryptoException.InvalidInput()
    }
}

internal fun requireStandardSec1PublicKey(
    publicKey: ByteArray,
    compressedLength: Int,
    uncompressedLength: Int,
) {
    // Provider parsers may accept hybrid encodings. A strict shape boundary
    // prevents the same point from acquiring an undocumented key identity.
    when (publicKey.size) {
        compressedLength -> requireCompressedSec1PublicKey(publicKey, compressedLength)
        uncompressedLength -> {
            if (publicKey.firstOrNull() != SEC1_UNCOMPRESSED_PREFIX) {
                throw ReallyMeCryptoException.InvalidInput()
            }
        }
        else -> throw ReallyMeCryptoException.InvalidInput()
    }
}
