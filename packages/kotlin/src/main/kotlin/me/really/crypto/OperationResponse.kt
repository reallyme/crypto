// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

internal object ReallyMeCryptoOperationResponseNative {
    @JvmStatic
    external fun processOperationResponseNative(request: ByteArray): ByteArray?

    @JvmStatic
    external fun processOperationResponseJsonNative(requestJson: ByteArray): ByteArray?
}

internal fun requireNativeOperationResponse(response: ByteArray?): ByteArray =
    response ?: throw ReallyMeCryptoException.ProviderFailure()
