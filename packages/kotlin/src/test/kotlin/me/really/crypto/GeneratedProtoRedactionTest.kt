// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import com.google.protobuf.ByteString
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import me.really.crypto.v1.CryptoKeyPair
import me.really.crypto.v1.CryptoOperationRequest
import me.really.crypto.v1.CryptoOperationResponse
import me.really.crypto.v1.CryptoOperationResult
import me.really.crypto.v1.CryptoSignatureSignRequest

class GeneratedProtoRedactionTest {
    @Test
    fun operationOwnersDoNotRenderNestedSecretMaterial() {
        val publicKey = ByteString.copyFromUtf8("public-marker")
        val secretKey = ByteString.copyFromUtf8("secret-marker")
        val keyPair = CryptoKeyPair.newBuilder()
            .setPublicKey(publicKey)
            .setSecretKey(secretKey)
            .build()
        val result = CryptoOperationResult.newBuilder()
            .setSignatureGenerateKeyPair(keyPair)
            .build()
        val response = CryptoOperationResponse.newBuilder()
            .setResult(result)
            .build()

        assertRedacted(result.toString(), listOf(publicKey, secretKey))
        assertRedacted(response.toString(), listOf(publicKey, secretKey))

        val signRequest = CryptoSignatureSignRequest.newBuilder()
            .setMessage(publicKey)
            .setSecretKey(secretKey)
            .build()
        val request = CryptoOperationRequest.newBuilder()
            .setSignatureSign(signRequest)
            .build()

        assertRedacted(request.toString(), listOf(publicKey, secretKey))
    }

    private fun assertRedacted(description: String, sensitiveValues: List<ByteString>) {
        assertTrue(description.contains("<redacted>"))
        for (sensitiveValue in sensitiveValues) {
            assertFalse(description.contains(sensitiveValue.toStringUtf8()))
        }
    }
}
