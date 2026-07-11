// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

public object ReallyMeHkdf {
    public const val MIN_INPUT_KEY_MATERIAL_LENGTH: Int = 1
    public const val MAX_INPUT_LENGTH: Int = 4096
    public const val MIN_OUTPUT_LENGTH: Int = 1
    public const val MAX_OUTPUT_LENGTH: Int = 4096

    public fun deriveSha256(
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int,
    ): ByteArray {
        validate(inputKeyMaterial, salt, info, outputLength)
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(inputKeyMaterial, salt, info))
        val output = ByteArray(outputLength)
        generator.generateBytes(output, 0, output.size)
        return output
    }

    private fun validate(
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int,
    ) {
        if (inputKeyMaterial.size !in MIN_INPUT_KEY_MATERIAL_LENGTH..MAX_INPUT_LENGTH ||
            salt.size > MAX_INPUT_LENGTH ||
            info.size > MAX_INPUT_LENGTH ||
            outputLength !in MIN_OUTPUT_LENGTH..MAX_OUTPUT_LENGTH
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }
}
