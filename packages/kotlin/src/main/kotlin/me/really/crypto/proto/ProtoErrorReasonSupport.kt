// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto.proto

internal fun reasonCodeMatchesBranch(
    branch: ReallyMeCryptoWireErrorBranch,
    reasonCode: Int,
): Boolean =
    when (branch) {
        ReallyMeCryptoWireErrorBranch.PRIMITIVE -> reasonCode in 100..199
        ReallyMeCryptoWireErrorBranch.PROVIDER -> reasonCode in 200..299
        ReallyMeCryptoWireErrorBranch.BACKEND -> reasonCode in 300..399
    }
